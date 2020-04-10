/*
 * Copyright (c) 2000-2018 Apple Inc. All rights reserved.
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
 */
/*
 * Mach Operating System
 * Copyright (c) 1992-1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <mach/exception_types.h>
#include <mach/i386/thread_status.h>
#include <mach/i386/fp_reg.h>

#include <kern/mach_param.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <kern/assert.h>

#include <libkern/OSAtomic.h>

#include <architecture/i386/pio.h>
#include <i386/cpuid.h>
#include <i386/fpu.h>
#include <i386/proc_reg.h>
#include <i386/misc_protos.h>
#include <i386/thread.h>
#include <i386/trap.h>

xstate_t        fpu_capability = UNDEFINED;     /* extended state capability */
xstate_t        fpu_default = UNDEFINED;        /* default extended state */

#define ALIGNED(addr, size)      (((uintptr_t)(addr)&((size)-1))==0)

/* Forward */

extern void             fpinit(void);
extern void             fp_save(
	thread_t        thr_act);
extern void             fp_load(
	thread_t        thr_act);

static void configure_mxcsr_capability_mask(x86_ext_thread_state_t *fps);
static xstate_t thread_xstate(thread_t);

x86_ext_thread_state_t  initial_fp_state __attribute((aligned(64)));
x86_ext_thread_state_t  default_avx512_state __attribute((aligned(64)));
x86_ext_thread_state_t  default_avx_state __attribute((aligned(64)));
x86_ext_thread_state_t  default_fx_state __attribute((aligned(64)));

/* Global MXCSR capability bitmask */
static unsigned int mxcsr_capability_mask;

#define fninit() \
	__asm__ volatile("fninit")

#define fnstcw(control) \
	__asm__("fnstcw %0" : "=m" (*(unsigned short *)(control)))

#define fldcw(control) \
	__asm__ volatile("fldcw %0" : : "m" (*(unsigned short *) &(control)) )

#define fnclex() \
	__asm__ volatile("fnclex")

#define fnsave(state)  \
	__asm__ volatile("fnsave %0" : "=m" (*state))

#define frstor(state) \
	__asm__ volatile("frstor %0" : : "m" (state))

#define fwait() \
	__asm__("fwait");

static inline void
fxrstor(struct x86_fx_thread_state *a)
{
	__asm__ __volatile__ ("fxrstor %0" ::  "m" (*a));
}

static inline void
fxsave(struct x86_fx_thread_state *a)
{
	__asm__ __volatile__ ("fxsave %0" : "=m" (*a));
}

static inline void
fxrstor64(struct x86_fx_thread_state *a)
{
	__asm__ __volatile__ ("fxrstor64 %0" ::  "m" (*a));
}

static inline void
fxsave64(struct x86_fx_thread_state *a)
{
	__asm__ __volatile__ ("fxsave64 %0" : "=m" (*a));
}

#if !defined(RC_HIDE_XNU_J137)
#define IS_VALID_XSTATE(x)      ((x) == FP || (x) == AVX || (x) == AVX512)
#else
#define IS_VALID_XSTATE(x)      ((x) == FP || (x) == AVX)
#endif

zone_t          ifps_zone[] = {
	[FP]     = NULL,
	[AVX]    = NULL,
#if !defined(RC_HIDE_XNU_J137)
	[AVX512] = NULL
#endif
};
static uint32_t fp_state_size[] = {
	[FP]     = sizeof(struct x86_fx_thread_state),
	[AVX]    = sizeof(struct x86_avx_thread_state),
#if !defined(RC_HIDE_XNU_J137)
	[AVX512] = sizeof(struct x86_avx512_thread_state)
#endif
};

static const char *xstate_name[] = {
	[UNDEFINED] = "UNDEFINED",
	[FP] = "FP",
	[AVX] = "AVX",
#if !defined(RC_HIDE_XNU_J137)
	[AVX512] = "AVX512"
#endif
};

#if !defined(RC_HIDE_XNU_J137)
#define fpu_ZMM_capable (fpu_capability == AVX512)
#define fpu_YMM_capable (fpu_capability == AVX || fpu_capability == AVX512)
/*
 * On-demand AVX512 support
 * ------------------------
 * On machines with AVX512 support, by default, threads are created with
 * AVX512 masked off in XCR0 and an AVX-sized savearea is used. However, AVX512
 * capabilities are advertised in the commpage and via sysctl. If a thread
 * opts to use AVX512 instructions, the first will result in a #UD exception.
 * Faulting AVX512 intructions are recognizable by their unique prefix.
 * This exception results in the thread being promoted to use an AVX512-sized
 * savearea and for the AVX512 bit masks being set in its XCR0. The faulting
 * instruction is re-driven and the thread can proceed to perform AVX512
 * operations.
 *
 * In addition to AVX512 instructions causing promotion, the thread_set_state()
 * primitive with an AVX512 state flavor result in promotion.
 *
 * AVX512 promotion of the first thread in a task causes the default xstate
 * of the task to be promoted so that any subsequently created or subsequently
 * DNA-faulted thread will have AVX512 xstate and it will not need to fault-in
 * a promoted xstate.
 *
 * Two savearea zones are used: the default pool of AVX-sized (832 byte) areas
 * and a second pool of larger AVX512-sized (2688 byte) areas.
 *
 * Note the initial state value is an AVX512 object but that the AVX initial
 * value is a subset of it.
 */
#else
#define fpu_YMM_capable (fpu_capability == AVX)
#endif
static uint32_t cpuid_reevaluated = 0;

static void fpu_store_registers(void *, boolean_t);
static void fpu_load_registers(void *);

#if !defined(RC_HIDE_XNU_J137)
static const uint32_t xstate_xmask[] = {
	[FP] =          FP_XMASK,
	[AVX] =         AVX_XMASK,
	[AVX512] =      AVX512_XMASK
};
#else
static const uint32_t xstate_xmask[] = {
	[FP] =          FP_XMASK,
	[AVX] =         AVX_XMASK,
};
#endif

static inline void
xsave(struct x86_fx_thread_state *a, uint32_t rfbm)
{
	__asm__ __volatile__ ("xsave %0" :"=m" (*a) : "a"(rfbm), "d"(0));
}

static inline void
xsave64(struct x86_fx_thread_state *a, uint32_t rfbm)
{
	__asm__ __volatile__ ("xsave64 %0" :"=m" (*a) : "a"(rfbm), "d"(0));
}

static inline void
xrstor(struct x86_fx_thread_state *a, uint32_t rfbm)
{
	__asm__ __volatile__ ("xrstor %0" ::  "m" (*a), "a"(rfbm), "d"(0));
}

static inline void
xrstor64(struct x86_fx_thread_state *a, uint32_t rfbm)
{
	__asm__ __volatile__ ("xrstor64 %0" ::  "m" (*a), "a"(rfbm), "d"(0));
}

#if !defined(RC_HIDE_XNU_J137)
__unused static inline void
vzeroupper(void)
{
	__asm__ __volatile__ ("vzeroupper" ::);
}

static boolean_t fpu_thread_promote_avx512(thread_t);   /* Forward */


/*
 * Furthermore, make compile-time asserts that no padding creeps into structures
 * for which we're doing this.
 */
#define ASSERT_PACKED(t, m1, m2, n, mt)                 \
extern char assert_packed_ ## t ## _ ## m1 ## _ ## m2   \
	[(offsetof(t,m2) - offsetof(t,m1) == (n - 1)*sizeof(mt)) ? 1 : -1]

ASSERT_PACKED(x86_avx_state32_t, fpu_ymmh0, fpu_ymmh7, 8, _STRUCT_XMM_REG);

ASSERT_PACKED(x86_avx_state64_t, fpu_ymmh0, fpu_ymmh15, 16, _STRUCT_XMM_REG);

ASSERT_PACKED(x86_avx512_state32_t, fpu_k0, fpu_k7, 8, _STRUCT_OPMASK_REG);
ASSERT_PACKED(x86_avx512_state32_t, fpu_ymmh0, fpu_ymmh7, 8, _STRUCT_XMM_REG);
ASSERT_PACKED(x86_avx512_state32_t, fpu_zmmh0, fpu_zmmh7, 8, _STRUCT_YMM_REG);

ASSERT_PACKED(x86_avx512_state64_t, fpu_k0, fpu_k7, 8, _STRUCT_OPMASK_REG);
ASSERT_PACKED(x86_avx512_state64_t, fpu_ymmh0, fpu_ymmh15, 16, _STRUCT_XMM_REG);
ASSERT_PACKED(x86_avx512_state64_t, fpu_zmmh0, fpu_zmmh15, 16, _STRUCT_YMM_REG);
ASSERT_PACKED(x86_avx512_state64_t, fpu_zmm16, fpu_zmm31, 16, _STRUCT_ZMM_REG);

#if defined(DEBUG_AVX512)

#define DBG(x...)       kprintf("DBG: " x)

typedef struct { uint8_t byte[8]; }  opmask_t;
typedef struct { uint8_t byte[16]; } xmm_t;
typedef struct { uint8_t byte[32]; } ymm_t;
typedef struct { uint8_t byte[64]; } zmm_t;

static void
DBG_AVX512_STATE(struct x86_avx512_thread_state *sp)
{
	int     i, j;
	xmm_t *xmm  = (xmm_t *) &sp->fp.fx_XMM_reg;
	xmm_t *ymmh = (xmm_t *) &sp->x_YMM_Hi128;
	ymm_t *zmmh = (ymm_t *) &sp->x_ZMM_Hi256;
	zmm_t *zmm  = (zmm_t *) &sp->x_Hi16_ZMM;
	opmask_t *k = (opmask_t *) &sp->x_Opmask;

	kprintf("x_YMM_Hi128: %lu\n", offsetof(struct x86_avx512_thread_state, x_YMM_Hi128));
	kprintf("x_Opmask:    %lu\n", offsetof(struct x86_avx512_thread_state, x_Opmask));
	kprintf("x_ZMM_Hi256: %lu\n", offsetof(struct x86_avx512_thread_state, x_ZMM_Hi256));
	kprintf("x_Hi16_ZMM:  %lu\n", offsetof(struct x86_avx512_thread_state, x_Hi16_ZMM));

	kprintf("XCR0:   0x%016llx\n", xgetbv(XCR0));
	kprintf("XINUSE: 0x%016llx\n", xgetbv(1));

	/* Print all ZMM registers */
	for (i = 0; i < 16; i++) {
		kprintf("zmm%d:\t0x", i);
		for (j = 0; j < 16; j++) {
			kprintf("%02x", xmm[i].byte[j]);
		}
		for (j = 0; j < 16; j++) {
			kprintf("%02x", ymmh[i].byte[j]);
		}
		for (j = 0; j < 32; j++) {
			kprintf("%02x", zmmh[i].byte[j]);
		}
		kprintf("\n");
	}
	for (i = 0; i < 16; i++) {
		kprintf("zmm%d:\t0x", 16 + i);
		for (j = 0; j < 64; j++) {
			kprintf("%02x", zmm[i].byte[j]);
		}
		kprintf("\n");
	}
	for (i = 0; i < 8; i++) {
		kprintf("k%d:\t0x", i);
		for (j = 0; j < 8; j++) {
			kprintf("%02x", k[i].byte[j]);
		}
		kprintf("\n");
	}

	kprintf("xstate_bv: 0x%016llx\n", sp->_xh.xstate_bv);
	kprintf("xcomp_bv:  0x%016llx\n", sp->_xh.xcomp_bv);
}
#else
#define DBG(x...)
static void
DBG_AVX512_STATE(__unused struct x86_avx512_thread_state *sp)
{
	return;
}
#endif /* DEBUG_AVX512 */

#endif

#if     DEBUG
static inline unsigned short
fnstsw(void)
{
	unsigned short status;
	__asm__ volatile ("fnstsw %0" : "=ma" (status));
	return status;
}
#endif

/*
 * Configure the initial FPU state presented to new threads.
 * Determine the MXCSR capability mask, which allows us to mask off any
 * potentially unsafe "reserved" bits before restoring the FPU context.
 * *Not* per-cpu, assumes symmetry.
 */

static void
configure_mxcsr_capability_mask(x86_ext_thread_state_t *fps)
{
	/* XSAVE requires a 64 byte aligned store */
	assert(ALIGNED(fps, 64));
	/* Clear, to prepare for the diagnostic FXSAVE */
	bzero(fps, sizeof(*fps));

	fpinit();
	fpu_store_registers(fps, FALSE);

	mxcsr_capability_mask = fps->fx.fx_MXCSR_MASK;

	/* Set default mask value if necessary */
	if (mxcsr_capability_mask == 0) {
		mxcsr_capability_mask = 0xffbf;
	}

	/* Clear vector register store */
	bzero(&fps->fx.fx_XMM_reg[0][0], sizeof(fps->fx.fx_XMM_reg));
	bzero(fps->avx.x_YMM_Hi128, sizeof(fps->avx.x_YMM_Hi128));
#if !defined(RC_HIDE_XNU_J137)
	if (fpu_ZMM_capable) {
		bzero(fps->avx512.x_ZMM_Hi256, sizeof(fps->avx512.x_ZMM_Hi256));
		bzero(fps->avx512.x_Hi16_ZMM, sizeof(fps->avx512.x_Hi16_ZMM));
		bzero(fps->avx512.x_Opmask, sizeof(fps->avx512.x_Opmask));
	}
#endif

	fps->fx.fp_valid = TRUE;
	fps->fx.fp_save_layout = fpu_YMM_capable ? XSAVE32: FXSAVE32;
	fpu_load_registers(fps);

	if (fpu_ZMM_capable) {
		xsave64((struct x86_fx_thread_state *)&default_avx512_state, xstate_xmask[AVX512]);
	}
	if (fpu_YMM_capable) {
		xsave64((struct x86_fx_thread_state *)&default_avx_state, xstate_xmask[AVX]);
	} else {
		fxsave64((struct x86_fx_thread_state *)&default_fx_state);
	}

	/* Poison values to trap unsafe usage */
	fps->fx.fp_valid = 0xFFFFFFFF;
	fps->fx.fp_save_layout = FP_UNUSED;

	/* Re-enable FPU/SSE DNA exceptions */
	set_ts();
}

int fpsimd_fault_popc = 0;
/*
 * Look for FPU and initialize it.
 * Called on each CPU.
 */
void
init_fpu(void)
{
#if     DEBUG
	unsigned short  status;
	unsigned short  control;
#endif
	/*
	 * Check for FPU by initializing it,
	 * then trying to read the correct bit patterns from
	 * the control and status registers.
	 */
	set_cr0((get_cr0() & ~(CR0_EM | CR0_TS)) | CR0_NE);       /* allow use of FPU */
	fninit();
#if     DEBUG
	status = fnstsw();
	fnstcw(&control);

	assert(((status & 0xff) == 0) && ((control & 0x103f) == 0x3f));
#endif
	/* Advertise SSE support */
	if (cpuid_features() & CPUID_FEATURE_FXSR) {
		set_cr4(get_cr4() | CR4_OSFXS);
		/* And allow SIMD exceptions if present */
		if (cpuid_features() & CPUID_FEATURE_SSE) {
			set_cr4(get_cr4() | CR4_OSXMM);
		}
	} else {
		panic("fpu is not FP_FXSR");
	}

	fpu_capability = fpu_default = FP;

	PE_parse_boot_argn("fpsimd_fault_popc", &fpsimd_fault_popc, sizeof(fpsimd_fault_popc));

#if !defined(RC_HIDE_XNU_J137)
	static boolean_t is_avx512_enabled = TRUE;
	if (cpu_number() == master_cpu) {
		if (cpuid_leaf7_features() & CPUID_LEAF7_FEATURE_AVX512F) {
			PE_parse_boot_argn("avx512", &is_avx512_enabled, sizeof(boolean_t));
			kprintf("AVX512 supported %s\n",
			    is_avx512_enabled ? "and enabled" : "but disabled");
		}
	}
#endif

	/* Configure the XSAVE context mechanism if the processor supports
	 * AVX/YMM registers
	 */
	if (cpuid_features() & CPUID_FEATURE_XSAVE) {
		cpuid_xsave_leaf_t *xs0p = &cpuid_info()->cpuid_xsave_leaf[0];
#if !defined(RC_HIDE_XNU_J137)
		if (is_avx512_enabled &&
		    (xs0p->extended_state[eax] & XFEM_ZMM) == XFEM_ZMM) {
			assert(xs0p->extended_state[eax] & XFEM_SSE);
			assert(xs0p->extended_state[eax] & XFEM_YMM);
			fpu_capability = AVX512;
			/* XSAVE container size for all features */
			set_cr4(get_cr4() | CR4_OSXSAVE);
			xsetbv(0, AVX512_XMASK);
			/* Re-evaluate CPUID, once, to reflect OSXSAVE */
			if (OSCompareAndSwap(0, 1, &cpuid_reevaluated)) {
				cpuid_set_info();
			}
			/* Verify that now selected state can be accommodated */
			assert(xs0p->extended_state[ebx] == fp_state_size[AVX512]);
			/*
			 * AVX set until AVX512 is used.
			 * See comment above about on-demand AVX512 support.
			 */
			xsetbv(0, AVX_XMASK);
			fpu_default = AVX;
		} else
#endif
		if (xs0p->extended_state[eax] & XFEM_YMM) {
			assert(xs0p->extended_state[eax] & XFEM_SSE);
			fpu_capability = AVX;
			fpu_default = AVX;
			/* XSAVE container size for all features */
			set_cr4(get_cr4() | CR4_OSXSAVE);
			xsetbv(0, AVX_XMASK);
			/* Re-evaluate CPUID, once, to reflect OSXSAVE */
			if (OSCompareAndSwap(0, 1, &cpuid_reevaluated)) {
				cpuid_set_info();
			}
			/* Verify that now selected state can be accommodated */
			assert(xs0p->extended_state[ebx] == fp_state_size[AVX]);
		}
	}

	if (cpu_number() == master_cpu) {
		kprintf("fpu_state: %s, state_size: %d\n",
		    xstate_name[fpu_capability],
		    fp_state_size[fpu_capability]);
	}

	fpinit();
	current_cpu_datap()->cpu_xstate = fpu_default;

	/*
	 * Trap wait instructions.  Turn off FPU for now.
	 */
	set_cr0(get_cr0() | CR0_TS | CR0_MP);
}

/*
 * Allocate and initialize FP state for specified xstate.
 * Don't load state.
 */
static void *
fp_state_alloc(xstate_t xs)
{
	struct x86_fx_thread_state *ifps;

	assert(ifps_zone[xs] != NULL);
	ifps = zalloc(ifps_zone[xs]);

#if     DEBUG
	if (!(ALIGNED(ifps, 64))) {
		panic("fp_state_alloc: %p, %u, %p, %u",
		    ifps, (unsigned) ifps_zone[xs]->elem_size,
		    (void *) ifps_zone[xs]->free_elements,
		    (unsigned) ifps_zone[xs]->alloc_size);
	}
#endif
	bzero(ifps, fp_state_size[xs]);

	return ifps;
}

static inline void
fp_state_free(void *ifps, xstate_t xs)
{
	assert(ifps_zone[xs] != NULL);
	zfree(ifps_zone[xs], ifps);
}

void
clear_fpu(void)
{
	set_ts();
}


static void
fpu_load_registers(void *fstate)
{
	struct x86_fx_thread_state *ifps = fstate;
	fp_save_layout_t layout = ifps->fp_save_layout;

	assert(current_task() == NULL ||                                \
	    (thread_is_64bit_addr(current_thread()) ?                        \
	    (layout == FXSAVE64 || layout == XSAVE64) :     \
	    (layout == FXSAVE32 || layout == XSAVE32)));
	assert(ALIGNED(ifps, 64));
	assert(ml_get_interrupts_enabled() == FALSE);

#if     DEBUG
	if (layout == XSAVE32 || layout == XSAVE64) {
		struct x86_avx_thread_state *iavx = fstate;
		unsigned i;
		/* Verify reserved bits in the XSAVE header*/
		if (iavx->_xh.xstate_bv & ~xstate_xmask[current_xstate()]) {
			panic("iavx->_xh.xstate_bv: 0x%llx", iavx->_xh.xstate_bv);
		}
		for (i = 0; i < sizeof(iavx->_xh.xhrsvd); i++) {
			if (iavx->_xh.xhrsvd[i]) {
				panic("Reserved bit set");
			}
		}
	}
	if (fpu_YMM_capable) {
		if (layout != XSAVE32 && layout != XSAVE64) {
			panic("Inappropriate layout: %u\n", layout);
		}
	}
#endif  /* DEBUG */

	switch (layout) {
	case FXSAVE64:
		fxrstor64(ifps);
		break;
	case FXSAVE32:
		fxrstor(ifps);
		break;
	case XSAVE64:
		xrstor64(ifps, xstate_xmask[current_xstate()]);
		break;
	case XSAVE32:
		xrstor(ifps, xstate_xmask[current_xstate()]);
		break;
	default:
		panic("fpu_load_registers() bad layout: %d\n", layout);
	}
}

static void
fpu_store_registers(void *fstate, boolean_t is64)
{
	struct x86_fx_thread_state *ifps = fstate;
	assert(ALIGNED(ifps, 64));
	xstate_t xs = current_xstate();
	switch (xs) {
	case FP:
		if (is64) {
			fxsave64(fstate);
			ifps->fp_save_layout = FXSAVE64;
		} else {
			fxsave(fstate);
			ifps->fp_save_layout = FXSAVE32;
		}
		break;
	case AVX:
#if !defined(RC_HIDE_XNU_J137)
	case AVX512:
#endif
		if (is64) {
			xsave64(ifps, xstate_xmask[xs]);
			ifps->fp_save_layout = XSAVE64;
		} else {
			xsave(ifps, xstate_xmask[xs]);
			ifps->fp_save_layout = XSAVE32;
		}
		break;
	default:
		panic("fpu_store_registers() bad xstate: %d\n", xs);
	}
}

/*
 * Initialize FP handling.
 */

void
fpu_module_init(void)
{
	if (!IS_VALID_XSTATE(fpu_default)) {
		panic("fpu_module_init: invalid extended state %u\n",
		    fpu_default);
	}

	/* We explicitly choose an allocation size of 13 pages = 64 * 832
	 * to eliminate waste for the 832 byte sized
	 * AVX XSAVE register save area.
	 */
	ifps_zone[fpu_default] = zinit(fp_state_size[fpu_default],
	    thread_max * fp_state_size[fpu_default],
	    64 * fp_state_size[fpu_default],
	    "x86 fpsave state");

	/* To maintain the required alignment, disable
	 * zone debugging for this zone as that appends
	 * 16 bytes to each element.
	 */
	zone_change(ifps_zone[fpu_default], Z_ALIGNMENT_REQUIRED, TRUE);

#if !defined(RC_HIDE_XNU_J137)
	/*
	 * If AVX512 is supported, create a separate savearea zone.
	 * with allocation size: 19 pages = 32 * 2668
	 */
	if (fpu_capability == AVX512) {
		ifps_zone[AVX512] = zinit(fp_state_size[AVX512],
		    thread_max * fp_state_size[AVX512],
		    32 * fp_state_size[AVX512],
		    "x86 avx512 save state");
		zone_change(ifps_zone[AVX512], Z_ALIGNMENT_REQUIRED, TRUE);
	}
#endif

	/* Determine MXCSR reserved bits and configure initial FPU state*/
	configure_mxcsr_capability_mask(&initial_fp_state);
}

/*
 * Context switch fpu state.
 * Always save old thread`s FPU context but don't load new .. allow that to fault-in.
 * Switch to the new task's xstate.
 */

void
fpu_switch_context(thread_t old, thread_t new)
{
	struct x86_fx_thread_state      *ifps;
	cpu_data_t *cdp = current_cpu_datap();
	xstate_t new_xstate = new ? thread_xstate(new) : fpu_default;

	assert(ml_get_interrupts_enabled() == FALSE);
	ifps = (old)->machine.ifps;
#if     DEBUG
	if (ifps && ((ifps->fp_valid != FALSE) && (ifps->fp_valid != TRUE))) {
		panic("ifps->fp_valid: %u\n", ifps->fp_valid);
	}
#endif
	if (ifps != 0 && (ifps->fp_valid == FALSE)) {
		/* Clear CR0.TS in preparation for the FP context save. In
		 * theory, this shouldn't be necessary since a live FPU should
		 * indicate that TS is clear. However, various routines
		 * (such as sendsig & sigreturn) manipulate TS directly.
		 */
		clear_ts();
		/* registers are in FPU - save to memory */
		boolean_t is64 = (thread_is_64bit_addr(old) &&
		    is_saved_state64(old->machine.iss));

		fpu_store_registers(ifps, is64);
		ifps->fp_valid = TRUE;

		if (fpu_ZMM_capable && (cdp->cpu_xstate == AVX512)) {
			xrstor64((struct x86_fx_thread_state *)&default_avx512_state, xstate_xmask[AVX512]);
		} else if (fpu_YMM_capable) {
			xrstor64((struct x86_fx_thread_state *) &default_avx_state, xstate_xmask[AVX]);
		} else {
			fxrstor64((struct x86_fx_thread_state *)&default_fx_state);
		}
	}

	assertf(fpu_YMM_capable ? (xgetbv(XCR0) == xstate_xmask[cdp->cpu_xstate]) : TRUE, "XCR0 mismatch: 0x%llx 0x%x 0x%x", xgetbv(XCR0), cdp->cpu_xstate, xstate_xmask[cdp->cpu_xstate]);
	if (new_xstate != (xstate_t) cdp->cpu_xstate) {
		DBG("fpu_switch_context(%p,%p) new xstate: %s\n",
		    old, new, xstate_name[new_xstate]);
		xsetbv(0, xstate_xmask[new_xstate]);
		cdp->cpu_xstate = new_xstate;
	}
	set_ts();
}


/*
 * Free a FPU save area.
 * Called only when thread terminating - no locking necessary.
 */
void
fpu_free(thread_t thread, void *fps)
{
	pcb_t   pcb = THREAD_TO_PCB(thread);

	fp_state_free(fps, pcb->xstate);
	pcb->xstate = UNDEFINED;
}

/*
 * Set the floating-point state for a thread based
 * on the FXSave formatted data. This is basically
 * the same as fpu_set_state except it uses the
 * expanded data structure.
 * If the thread is not the current thread, it is
 * not running (held).  Locking needed against
 * concurrent fpu_set_state or fpu_get_state.
 */
kern_return_t
fpu_set_fxstate(
	thread_t        thr_act,
	thread_state_t  tstate,
	thread_flavor_t f)
{
	struct x86_fx_thread_state      *ifps;
	struct x86_fx_thread_state      *new_ifps;
	x86_float_state64_t             *state;
	pcb_t                           pcb;
	boolean_t                       old_valid, fresh_state = FALSE;

	if (fpu_capability == UNDEFINED) {
		return KERN_FAILURE;
	}

	if ((f == x86_AVX_STATE32 || f == x86_AVX_STATE64) &&
	    fpu_capability < AVX) {
		return KERN_FAILURE;
	}

#if !defined(RC_HIDE_XNU_J137)
	if ((f == x86_AVX512_STATE32 || f == x86_AVX512_STATE64) &&
	    thread_xstate(thr_act) == AVX) {
		if (!fpu_thread_promote_avx512(thr_act)) {
			return KERN_FAILURE;
		}
	}
#endif

	state = (x86_float_state64_t *)tstate;

	assert(thr_act != THREAD_NULL);
	pcb = THREAD_TO_PCB(thr_act);

	if (state == NULL) {
		/*
		 * new FPU state is 'invalid'.
		 * Deallocate the fp state if it exists.
		 */
		simple_lock(&pcb->lock, LCK_GRP_NULL);

		ifps = pcb->ifps;
		pcb->ifps = 0;

		simple_unlock(&pcb->lock);

		if (ifps != 0) {
			fp_state_free(ifps, thread_xstate(thr_act));
		}
	} else {
		/*
		 * Valid incoming state. Allocate the fp state if there is none.
		 */
		new_ifps = 0;
Retry:
		simple_lock(&pcb->lock, LCK_GRP_NULL);

		ifps = pcb->ifps;
		if (ifps == 0) {
			if (new_ifps == 0) {
				simple_unlock(&pcb->lock);
				new_ifps = fp_state_alloc(thread_xstate(thr_act));
				goto Retry;
			}
			ifps = new_ifps;
			new_ifps = 0;
			pcb->ifps = ifps;
			pcb->xstate = thread_xstate(thr_act);
			fresh_state = TRUE;
		}

		/*
		 * now copy over the new data.
		 */

		old_valid = ifps->fp_valid;

#if     DEBUG || DEVELOPMENT
		if ((fresh_state == FALSE) && (old_valid == FALSE) && (thr_act != current_thread())) {
			panic("fpu_set_fxstate inconsistency, thread: %p not stopped", thr_act);
		}
#endif
		/*
		 * Clear any reserved bits in the MXCSR to prevent a GPF
		 * when issuing an FXRSTOR.
		 */

		state->fpu_mxcsr &= mxcsr_capability_mask;

		__nochk_bcopy((char *)&state->fpu_fcw, (char *)ifps, fp_state_size[FP]);

		switch (thread_xstate(thr_act)) {
		case UNDEFINED_FULL:
		case FP_FULL:
		case AVX_FULL:
		case AVX512_FULL:
			panic("fpu_set_fxstate() INVALID xstate: 0x%x", thread_xstate(thr_act));
			break;

		case UNDEFINED:
			panic("fpu_set_fxstate() UNDEFINED xstate");
			break;
		case FP:
			ifps->fp_save_layout = thread_is_64bit_addr(thr_act) ? FXSAVE64 : FXSAVE32;
			break;
		case AVX: {
			struct x86_avx_thread_state *iavx = (void *) ifps;
			x86_avx_state64_t *xs = (x86_avx_state64_t *) state;

			iavx->fp.fp_save_layout = thread_is_64bit_addr(thr_act) ? XSAVE64 : XSAVE32;

			/* Sanitize XSAVE header */
			bzero(&iavx->_xh.xhrsvd[0], sizeof(iavx->_xh.xhrsvd));
			iavx->_xh.xstate_bv = AVX_XMASK;
			iavx->_xh.xcomp_bv  = 0;

			if (f == x86_AVX_STATE32) {
				__nochk_bcopy(&xs->fpu_ymmh0, iavx->x_YMM_Hi128, 8 * sizeof(_STRUCT_XMM_REG));
			} else if (f == x86_AVX_STATE64) {
				__nochk_bcopy(&xs->fpu_ymmh0, iavx->x_YMM_Hi128, 16 * sizeof(_STRUCT_XMM_REG));
			} else {
				iavx->_xh.xstate_bv = (XFEM_SSE | XFEM_X87);
			}
			break;
		}
#if !defined(RC_HIDE_XNU_J137)
		case AVX512: {
			struct x86_avx512_thread_state *iavx = (void *) ifps;
			union {
				thread_state_t       ts;
				x86_avx512_state32_t *s32;
				x86_avx512_state64_t *s64;
			} xs = { .ts = tstate };

			iavx->fp.fp_save_layout = thread_is_64bit_addr(thr_act) ? XSAVE64 : XSAVE32;

			/* Sanitize XSAVE header */
			bzero(&iavx->_xh.xhrsvd[0], sizeof(iavx->_xh.xhrsvd));
			iavx->_xh.xstate_bv = AVX512_XMASK;
			iavx->_xh.xcomp_bv  = 0;

			switch (f) {
			case x86_AVX512_STATE32:
				__nochk_bcopy(&xs.s32->fpu_k0, iavx->x_Opmask, 8 * sizeof(_STRUCT_OPMASK_REG));
				__nochk_bcopy(&xs.s32->fpu_zmmh0, iavx->x_ZMM_Hi256, 8 * sizeof(_STRUCT_YMM_REG));
				__nochk_bcopy(&xs.s32->fpu_ymmh0, iavx->x_YMM_Hi128, 8 * sizeof(_STRUCT_XMM_REG));
				DBG_AVX512_STATE(iavx);
				break;
			case x86_AVX_STATE32:
				__nochk_bcopy(&xs.s32->fpu_ymmh0, iavx->x_YMM_Hi128, 8 * sizeof(_STRUCT_XMM_REG));
				break;
			case x86_AVX512_STATE64:
				__nochk_bcopy(&xs.s64->fpu_k0, iavx->x_Opmask, 8 * sizeof(_STRUCT_OPMASK_REG));
				__nochk_bcopy(&xs.s64->fpu_zmm16, iavx->x_Hi16_ZMM, 16 * sizeof(_STRUCT_ZMM_REG));
				__nochk_bcopy(&xs.s64->fpu_zmmh0, iavx->x_ZMM_Hi256, 16 * sizeof(_STRUCT_YMM_REG));
				__nochk_bcopy(&xs.s64->fpu_ymmh0, iavx->x_YMM_Hi128, 16 * sizeof(_STRUCT_XMM_REG));
				DBG_AVX512_STATE(iavx);
				break;
			case x86_AVX_STATE64:
				__nochk_bcopy(&xs.s64->fpu_ymmh0, iavx->x_YMM_Hi128, 16 * sizeof(_STRUCT_XMM_REG));
				break;
			}
			break;
		}
#endif
		}

		ifps->fp_valid = old_valid;

		if (old_valid == FALSE) {
			boolean_t istate = ml_set_interrupts_enabled(FALSE);
			ifps->fp_valid = TRUE;
			/* If altering the current thread's state, disable FPU */
			if (thr_act == current_thread()) {
				set_ts();
			}

			ml_set_interrupts_enabled(istate);
		}

		simple_unlock(&pcb->lock);

		if (new_ifps != 0) {
			fp_state_free(new_ifps, thread_xstate(thr_act));
		}
	}
	return KERN_SUCCESS;
}

/*
 * Get the floating-point state for a thread.
 * If the thread is not the current thread, it is
 * not running (held).  Locking needed against
 * concurrent fpu_set_state or fpu_get_state.
 */
kern_return_t
fpu_get_fxstate(
	thread_t        thr_act,
	thread_state_t  tstate,
	thread_flavor_t f)
{
	struct x86_fx_thread_state      *ifps;
	x86_float_state64_t             *state;
	kern_return_t                   ret = KERN_FAILURE;
	pcb_t                           pcb;

	if (fpu_capability == UNDEFINED) {
		return KERN_FAILURE;
	}

	if ((f == x86_AVX_STATE32 || f == x86_AVX_STATE64) &&
	    fpu_capability < AVX) {
		return KERN_FAILURE;
	}

#if !defined(RC_HIDE_XNU_J137)
	if ((f == x86_AVX512_STATE32 || f == x86_AVX512_STATE64) &&
	    thread_xstate(thr_act) != AVX512) {
		return KERN_FAILURE;
	}
#endif

	state = (x86_float_state64_t *)tstate;

	assert(thr_act != THREAD_NULL);
	pcb = THREAD_TO_PCB(thr_act);

	simple_lock(&pcb->lock, LCK_GRP_NULL);

	ifps = pcb->ifps;
	if (ifps == 0) {
		/*
		 * No valid floating-point state.
		 */

		__nochk_bcopy((char *)&initial_fp_state, (char *)&state->fpu_fcw,
		    fp_state_size[FP]);

		simple_unlock(&pcb->lock);

		return KERN_SUCCESS;
	}
	/*
	 * Make sure we`ve got the latest fp state info
	 * If the live fpu state belongs to our target
	 */
	if (thr_act == current_thread()) {
		boolean_t       intr;

		intr = ml_set_interrupts_enabled(FALSE);

		clear_ts();
		fp_save(thr_act);
		clear_fpu();

		(void)ml_set_interrupts_enabled(intr);
	}
	if (ifps->fp_valid) {
		__nochk_bcopy((char *)ifps, (char *)&state->fpu_fcw, fp_state_size[FP]);
		switch (thread_xstate(thr_act)) {
		case UNDEFINED_FULL:
		case FP_FULL:
		case AVX_FULL:
		case AVX512_FULL:
			panic("fpu_get_fxstate() INVALID xstate: 0x%x", thread_xstate(thr_act));
			break;

		case UNDEFINED:
			panic("fpu_get_fxstate() UNDEFINED xstate");
			break;
		case FP:
			break;                  /* already done */
		case AVX: {
			struct x86_avx_thread_state *iavx = (void *) ifps;
			x86_avx_state64_t *xs = (x86_avx_state64_t *) state;
			if (f == x86_AVX_STATE32) {
				__nochk_bcopy(iavx->x_YMM_Hi128, &xs->fpu_ymmh0, 8 * sizeof(_STRUCT_XMM_REG));
			} else if (f == x86_AVX_STATE64) {
				__nochk_bcopy(iavx->x_YMM_Hi128, &xs->fpu_ymmh0, 16 * sizeof(_STRUCT_XMM_REG));
			}
			break;
		}
#if !defined(RC_HIDE_XNU_J137)
		case AVX512: {
			struct x86_avx512_thread_state *iavx = (void *) ifps;
			union {
				thread_state_t       ts;
				x86_avx512_state32_t *s32;
				x86_avx512_state64_t *s64;
			} xs = { .ts = tstate };
			switch (f) {
			case x86_AVX512_STATE32:
				__nochk_bcopy(iavx->x_Opmask, &xs.s32->fpu_k0, 8 * sizeof(_STRUCT_OPMASK_REG));
				__nochk_bcopy(iavx->x_ZMM_Hi256, &xs.s32->fpu_zmmh0, 8 * sizeof(_STRUCT_YMM_REG));
				__nochk_bcopy(iavx->x_YMM_Hi128, &xs.s32->fpu_ymmh0, 8 * sizeof(_STRUCT_XMM_REG));
				DBG_AVX512_STATE(iavx);
				break;
			case x86_AVX_STATE32:
				__nochk_bcopy(iavx->x_YMM_Hi128, &xs.s32->fpu_ymmh0, 8 * sizeof(_STRUCT_XMM_REG));
				break;
			case x86_AVX512_STATE64:
				__nochk_bcopy(iavx->x_Opmask, &xs.s64->fpu_k0, 8 * sizeof(_STRUCT_OPMASK_REG));
				__nochk_bcopy(iavx->x_Hi16_ZMM, &xs.s64->fpu_zmm16, 16 * sizeof(_STRUCT_ZMM_REG));
				__nochk_bcopy(iavx->x_ZMM_Hi256, &xs.s64->fpu_zmmh0, 16 * sizeof(_STRUCT_YMM_REG));
				__nochk_bcopy(iavx->x_YMM_Hi128, &xs.s64->fpu_ymmh0, 16 * sizeof(_STRUCT_XMM_REG));
				DBG_AVX512_STATE(iavx);
				break;
			case x86_AVX_STATE64:
				__nochk_bcopy(iavx->x_YMM_Hi128, &xs.s64->fpu_ymmh0, 16 * sizeof(_STRUCT_XMM_REG));
				break;
			}
			break;
		}
#endif
		}

		ret = KERN_SUCCESS;
	}
	simple_unlock(&pcb->lock);

	return ret;
}



/*
 * the child thread is 'stopped' with the thread
 * mutex held and is currently not known by anyone
 * so no way for fpu state to get manipulated by an
 * outside agency -> no need for pcb lock
 */

void
fpu_dup_fxstate(
	thread_t        parent,
	thread_t        child)
{
	struct x86_fx_thread_state *new_ifps = NULL;
	boolean_t       intr;
	pcb_t           ppcb;
	xstate_t        xstate = thread_xstate(parent);

	ppcb = THREAD_TO_PCB(parent);

	if (ppcb->ifps == NULL) {
		return;
	}

	if (child->machine.ifps) {
		panic("fpu_dup_fxstate: child's ifps non-null");
	}

	new_ifps = fp_state_alloc(xstate);

	simple_lock(&ppcb->lock, LCK_GRP_NULL);

	if (ppcb->ifps != NULL) {
		struct x86_fx_thread_state *ifps = ppcb->ifps;
		/*
		 * Make sure we`ve got the latest fp state info
		 */
		if (current_thread() == parent) {
			intr = ml_set_interrupts_enabled(FALSE);
			assert(current_thread() == parent);
			clear_ts();
			fp_save(parent);
			clear_fpu();

			(void)ml_set_interrupts_enabled(intr);
		}

		if (ifps->fp_valid) {
			child->machine.ifps = new_ifps;
			child->machine.xstate = xstate;
			__nochk_bcopy((char *)(ppcb->ifps),
			    (char *)(child->machine.ifps),
			    fp_state_size[xstate]);

			/* Mark the new fp saved state as non-live. */
			/* Temporarily disabled: radar 4647827
			 * new_ifps->fp_valid = TRUE;
			 */

			/*
			 * Clear any reserved bits in the MXCSR to prevent a GPF
			 * when issuing an FXRSTOR.
			 */
			new_ifps->fx_MXCSR &= mxcsr_capability_mask;
			new_ifps = NULL;
		}
	}
	simple_unlock(&ppcb->lock);

	if (new_ifps != NULL) {
		fp_state_free(new_ifps, xstate);
	}
}

/*
 * Initialize FPU.
 * FNINIT programs the x87 control word to 0x37f, which matches
 * the desired default for macOS.
 */

void
fpinit(void)
{
	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	clear_ts();
	fninit();
#if DEBUG
	/* We skip this power-on-default verification sequence on
	 * non-DEBUG, as dirtying the x87 control word may slow down
	 * xsave/xrstor and affect energy use.
	 */
	unsigned short  control, control2;
	fnstcw(&control);
	control2 = control;
	control &= ~(FPC_PC | FPC_RC); /* Clear precision & rounding control */
	control |= (FPC_PC_64 |         /* Set precision */
	    FPC_RC_RN |                 /* round-to-nearest */
	    FPC_ZE |                    /* Suppress zero-divide */
	    FPC_OE |                    /*  and overflow */
	    FPC_UE |                    /*  underflow */
	    FPC_IE |                    /* Allow NaNQs and +-INF */
	    FPC_DE |                    /* Allow denorms as operands  */
	    FPC_PE);                    /* No trap for precision loss */
	assert(control == control2);
	fldcw(control);
#endif
	/* Initialize SSE/SSE2 */
	__builtin_ia32_ldmxcsr(0x1f80);
	if (fpu_YMM_capable) {
		vzeroall();
	} else {
		xmmzeroall();
	}
	ml_set_interrupts_enabled(istate);
}

/*
 * Coprocessor not present.
 */

uint64_t x86_isr_fp_simd_use;

void
fpnoextflt(void)
{
	boolean_t       intr;
	thread_t        thr_act;
	pcb_t           pcb;
	struct x86_fx_thread_state *ifps = 0;
	xstate_t        xstate = current_xstate();

	thr_act = current_thread();
	pcb = THREAD_TO_PCB(thr_act);

	if (pcb->ifps == 0 && !get_interrupt_level()) {
		ifps = fp_state_alloc(xstate);
		__nochk_bcopy((char *)&initial_fp_state, (char *)ifps,
		    fp_state_size[xstate]);
		if (!thread_is_64bit_addr(thr_act)) {
			ifps->fp_save_layout = fpu_YMM_capable ? XSAVE32 : FXSAVE32;
		} else {
			ifps->fp_save_layout = fpu_YMM_capable ? XSAVE64 : FXSAVE64;
		}
		ifps->fp_valid = TRUE;
	}
	intr = ml_set_interrupts_enabled(FALSE);

	clear_ts();                     /*  Enable FPU use */

	if (__improbable(get_interrupt_level())) {
		/* Track number of #DNA traps at interrupt context,
		 * which is likely suboptimal. Racy, but good enough.
		 */
		x86_isr_fp_simd_use++;
		/*
		 * Save current FP/SIMD context if valid
		 * Initialize live FP/SIMD registers
		 */
		if (pcb->ifps) {
			fp_save(thr_act);
		}
		fpinit();
	} else {
		if (pcb->ifps == 0) {
			pcb->ifps = ifps;
			pcb->xstate = xstate;
			ifps = 0;
		}
		/*
		 * Load this thread`s state into coprocessor live context.
		 */
		fp_load(thr_act);
	}
	(void)ml_set_interrupts_enabled(intr);

	if (ifps) {
		fp_state_free(ifps, xstate);
	}
}

/*
 * FPU overran end of segment.
 * Re-initialize FPU.  Floating point state is not valid.
 */

void
fpextovrflt(void)
{
	thread_t        thr_act = current_thread();
	pcb_t           pcb;
	struct x86_fx_thread_state *ifps;
	boolean_t       intr;
	xstate_t        xstate = current_xstate();

	intr = ml_set_interrupts_enabled(FALSE);

	if (get_interrupt_level()) {
		panic("FPU segment overrun exception at interrupt context\n");
	}
	if (current_task() == kernel_task) {
		panic("FPU segment overrun exception in kernel thread context\n");
	}

	/*
	 * This is a non-recoverable error.
	 * Invalidate the thread`s FPU state.
	 */
	pcb = THREAD_TO_PCB(thr_act);
	simple_lock(&pcb->lock, LCK_GRP_NULL);
	ifps = pcb->ifps;
	pcb->ifps = 0;
	simple_unlock(&pcb->lock);

	/*
	 * Re-initialize the FPU.
	 */
	clear_ts();
	fninit();

	/*
	 * And disable access.
	 */
	clear_fpu();

	(void)ml_set_interrupts_enabled(intr);

	if (ifps) {
		fp_state_free(ifps, xstate);
	}
}

extern void fpxlog(int, uint32_t, uint32_t, uint32_t);

/*
 * FPU error. Called by AST.
 */

void
fpexterrflt(void)
{
	thread_t        thr_act = current_thread();
	struct x86_fx_thread_state *ifps = thr_act->machine.ifps;
	boolean_t       intr;

	intr = ml_set_interrupts_enabled(FALSE);

	if (get_interrupt_level()) {
		panic("FPU error exception at interrupt context\n");
	}
	if (current_task() == kernel_task) {
		panic("FPU error exception in kernel thread context\n");
	}

	/*
	 * Save the FPU state and turn off the FPU.
	 */
	fp_save(thr_act);

	(void)ml_set_interrupts_enabled(intr);

	const uint32_t mask = ifps->fx_control &
	    (FPC_IM | FPC_DM | FPC_ZM | FPC_OM | FPC_UE | FPC_PE);
	const uint32_t xcpt = ~mask & (ifps->fx_status &
	    (FPS_IE | FPS_DE | FPS_ZE | FPS_OE | FPS_UE | FPS_PE));
	fpxlog(EXC_I386_EXTERR, ifps->fx_status, ifps->fx_control, xcpt);
}

/*
 * Save FPU state.
 *
 * Locking not needed:
 * .	if called from fpu_get_state, pcb already locked.
 * .	if called from fpnoextflt or fp_intr, we are single-cpu
 * .	otherwise, thread is running.
 * N.B.: Must be called with interrupts disabled
 */

void
fp_save(
	thread_t        thr_act)
{
	pcb_t pcb = THREAD_TO_PCB(thr_act);
	struct x86_fx_thread_state *ifps = pcb->ifps;

	assert(ifps != 0);
	if (ifps != 0 && !ifps->fp_valid) {
		assert((get_cr0() & CR0_TS) == 0);
		/* registers are in FPU */
		ifps->fp_valid = TRUE;
		fpu_store_registers(ifps, thread_is_64bit_addr(thr_act));
	}
}

/*
 * Restore FPU state from PCB.
 *
 * Locking not needed; always called on the current thread.
 */

void
fp_load(
	thread_t        thr_act)
{
	pcb_t pcb = THREAD_TO_PCB(thr_act);
	struct x86_fx_thread_state *ifps = pcb->ifps;

	assert(ifps);
#if     DEBUG
	if (ifps->fp_valid != FALSE && ifps->fp_valid != TRUE) {
		panic("fp_load() invalid fp_valid: %u, fp_save_layout: %u\n",
		    ifps->fp_valid, ifps->fp_save_layout);
	}
#endif

	if (ifps->fp_valid == FALSE) {
		fpinit();
	} else {
		fpu_load_registers(ifps);
	}
	ifps->fp_valid = FALSE;         /* in FPU */
}

/*
 * SSE arithmetic exception handling code.
 * Basically the same as the x87 exception handler with a different subtype
 */

void
fpSSEexterrflt(void)
{
	thread_t        thr_act = current_thread();
	struct x86_fx_thread_state *ifps = thr_act->machine.ifps;
	boolean_t       intr;

	intr = ml_set_interrupts_enabled(FALSE);

	if (get_interrupt_level()) {
		panic("SSE exception at interrupt context\n");
	}
	if (current_task() == kernel_task) {
		panic("SSE exception in kernel thread context\n");
	}

	/*
	 * Save the FPU state and turn off the FPU.
	 */
	fp_save(thr_act);

	(void)ml_set_interrupts_enabled(intr);
	/*
	 * Raise FPU exception.
	 * Locking not needed on pcb->ifps,
	 * since thread is running.
	 */
	const uint32_t mask = (ifps->fx_MXCSR >> 7) &
	    (FPC_IM | FPC_DM | FPC_ZM | FPC_OM | FPC_UE | FPC_PE);
	const uint32_t xcpt = ~mask & (ifps->fx_MXCSR &
	    (FPS_IE | FPS_DE | FPS_ZE | FPS_OE | FPS_UE | FPS_PE));
	fpxlog(EXC_I386_SSEEXTERR, ifps->fx_MXCSR, ifps->fx_MXCSR, xcpt);
}


#if !defined(RC_HIDE_XNU_J137)
/*
 * If a thread is using an AVX-sized savearea:
 * - allocate a new AVX512-sized  area,
 * - copy the 256-bit state into the 512-bit area,
 * - deallocate the smaller area
 */
static void
fpu_savearea_promote_avx512(thread_t thread)
{
	struct x86_avx_thread_state     *ifps = NULL;
	struct x86_avx512_thread_state  *ifps512 = NULL;
	pcb_t                           pcb = THREAD_TO_PCB(thread);
	boolean_t                       do_avx512_alloc = FALSE;

	DBG("fpu_upgrade_savearea(%p)\n", thread);

	simple_lock(&pcb->lock, LCK_GRP_NULL);

	ifps = pcb->ifps;
	if (ifps == NULL) {
		pcb->xstate = AVX512;
		simple_unlock(&pcb->lock);
		if (thread != current_thread()) {
			/* nothing to be done */

			return;
		}
		fpnoextflt();
		return;
	}

	if (pcb->xstate != AVX512) {
		do_avx512_alloc = TRUE;
	}
	simple_unlock(&pcb->lock);

	if (do_avx512_alloc == TRUE) {
		ifps512 = fp_state_alloc(AVX512);
	}

	simple_lock(&pcb->lock, LCK_GRP_NULL);
	if (thread == current_thread()) {
		boolean_t       intr;

		intr = ml_set_interrupts_enabled(FALSE);

		clear_ts();
		fp_save(thread);
		clear_fpu();

		xsetbv(0, AVX512_XMASK);
		current_cpu_datap()->cpu_xstate = AVX512;
		(void)ml_set_interrupts_enabled(intr);
	}
	assert(ifps->fp.fp_valid);

	/* Allocate an AVX512 savearea and copy AVX state into it */
	if (pcb->xstate != AVX512) {
		__nochk_bcopy(ifps, ifps512, fp_state_size[AVX]);
		pcb->ifps = ifps512;
		pcb->xstate = AVX512;
		ifps512 = NULL;
	} else {
		ifps = NULL;
	}
	/* The PCB lock is redundant in some scenarios given the higher level
	 * thread mutex, but its pre-emption disablement is relied upon here
	 */
	simple_unlock(&pcb->lock);

	if (ifps) {
		fp_state_free(ifps, AVX);
	}
	if (ifps512) {
		fp_state_free(ifps, AVX512);
	}
}

/*
 * Upgrade the calling thread to AVX512.
 */
boolean_t
fpu_thread_promote_avx512(thread_t thread)
{
	task_t          task = current_task();

	if (thread != current_thread()) {
		return FALSE;
	}
	if (!ml_fpu_avx512_enabled()) {
		return FALSE;
	}

	fpu_savearea_promote_avx512(thread);

	/* Racy but the task's xstate is only a hint */
	task->xstate = AVX512;

	return TRUE;
}


/*
 * Called from user_trap() when an invalid opcode fault is taken.
 * If the user is attempting an AVX512 instruction on a machine
 * that supports this, we switch the calling thread to use
 * a larger savearea, set its XCR0 bit mask to enable AVX512 and
 * return directly via thread_exception_return().
 * Otherwise simply return.
 */
#define MAX_X86_INSN_LENGTH (15)
int
fpUDflt(user_addr_t rip)
{
	uint8_t         instruction_prefix;
	boolean_t       is_AVX512_instruction = FALSE;
	user_addr_t     original_rip = rip;
	do {
		/* TODO: as an optimisation, copy up to the lesser of the
		 * next page boundary or maximal prefix length in one pass
		 * rather than issue multiple copyins
		 */
		if (copyin(rip, (char *) &instruction_prefix, 1)) {
			return 1;
		}
		DBG("fpUDflt(0x%016llx) prefix: 0x%x\n",
		    rip, instruction_prefix);
		/* TODO: determine more specifically which prefixes
		 * are sane possibilities for AVX512 insns
		 */
		switch (instruction_prefix) {
		case 0x2E:      /* CS segment override */
		case 0x36:      /* SS segment override */
		case 0x3E:      /* DS segment override */
		case 0x26:      /* ES segment override */
		case 0x64:      /* FS segment override */
		case 0x65:      /* GS segment override */
		case 0x66:      /* Operand-size override */
		case 0x67:      /* address-size override */
			/* Skip optional prefixes */
			rip++;
			if ((rip - original_rip) > MAX_X86_INSN_LENGTH) {
				return 1;
			}
			break;
		case 0x62:      /* EVEX */
		case 0xC5:      /* VEX 2-byte */
		case 0xC4:      /* VEX 3-byte */
			is_AVX512_instruction = TRUE;
			break;
		default:
			return 1;
		}
	} while (!is_AVX512_instruction);

	/* Here if we detect attempted execution of an AVX512 instruction */

	/*
	 * Fail if this machine doesn't support AVX512
	 */
	if (fpu_capability != AVX512) {
		return 1;
	}

	assert(xgetbv(XCR0) == AVX_XMASK);

	DBG("fpUDflt() switching xstate to AVX512\n");
	(void) fpu_thread_promote_avx512(current_thread());

	return 0;
}
#endif /* !defined(RC_HIDE_XNU_J137) */

void
fp_setvalid(boolean_t value)
{
	thread_t        thr_act = current_thread();
	struct x86_fx_thread_state *ifps = thr_act->machine.ifps;

	if (ifps) {
		ifps->fp_valid = value;

		if (value == TRUE) {
			boolean_t istate = ml_set_interrupts_enabled(FALSE);
			clear_fpu();
			ml_set_interrupts_enabled(istate);
		}
	}
}

boolean_t
ml_fpu_avx_enabled(void)
{
	return fpu_capability >= AVX;
}

#if !defined(RC_HIDE_XNU_J137)
boolean_t
ml_fpu_avx512_enabled(void)
{
	return fpu_capability == AVX512;
}
#endif

static xstate_t
task_xstate(task_t task)
{
	if (task == TASK_NULL) {
		return fpu_default;
	} else {
		return task->xstate;
	}
}

static xstate_t
thread_xstate(thread_t thread)
{
	xstate_t xs = THREAD_TO_PCB(thread)->xstate;
	if (xs == UNDEFINED) {
		return task_xstate(thread->task);
	} else {
		return xs;
	}
}

xstate_t
current_xstate(void)
{
	return thread_xstate(current_thread());
}

/*
 * Called when exec'ing between bitnesses.
 * If valid FPU state exists, adjust the layout.
 */
void
fpu_switch_addrmode(thread_t thread, boolean_t is_64bit)
{
	struct x86_fx_thread_state *ifps = thread->machine.ifps;
	mp_disable_preemption();

	if (ifps && ifps->fp_valid) {
		if (thread_xstate(thread) == FP) {
			ifps->fp_save_layout = is_64bit ? FXSAVE64 : FXSAVE32;
		} else {
			ifps->fp_save_layout = is_64bit ? XSAVE64 : XSAVE32;
		}
	}
	mp_enable_preemption();
}

static inline uint32_t
fpsimd_pop(uintptr_t ins, int sz)
{
	uint32_t rv = 0;


	while (sz >= 16) {
		uint32_t rv1, rv2;
		uint64_t *ins64 = (uint64_t *) ins;
		uint64_t *ins642 = (uint64_t *) (ins + 8);
		rv1 = __builtin_popcountll(*ins64);
		rv2 = __builtin_popcountll(*ins642);
		rv += rv1 + rv2;
		sz -= 16;
		ins += 16;
	}

	while (sz >= 4) {
		uint32_t *ins32 = (uint32_t *) ins;
		rv += __builtin_popcount(*ins32);
		sz -= 4;
		ins += 4;
	}

	while (sz > 0) {
		char *ins8 = (char *)ins;
		rv += __builtin_popcount(*ins8);
		sz--;
		ins++;
	}
	return rv;
}

uint32_t
thread_fpsimd_hash(thread_t ft)
{
	if (fpsimd_fault_popc == 0) {
		return 0;
	}

	uint32_t prv = 0;
	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	struct x86_fx_thread_state *pifps = THREAD_TO_PCB(ft)->ifps;

	if (pifps) {
		if (pifps->fp_valid) {
			prv = fpsimd_pop((uintptr_t) &pifps->fx_XMM_reg[0][0],
			    sizeof(pifps->fx_XMM_reg));
		} else {
			uintptr_t cr0 = get_cr0();
			clear_ts();
			fp_save(ft);
			prv = fpsimd_pop((uintptr_t) &pifps->fx_XMM_reg[0][0],
			    sizeof(pifps->fx_XMM_reg));
			pifps->fp_valid = FALSE;
			if (cr0 & CR0_TS) {
				set_cr0(cr0);
			}
		}
	}
	ml_set_interrupts_enabled(istate);
	return prv;
}
