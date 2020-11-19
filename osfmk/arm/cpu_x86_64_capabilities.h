/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
 */

#ifdef  PRIVATE

#ifndef _ARM_CPU_X86_64_CAPABILITIES_H
#define _ARM_CPU_X86_64_CAPABILITIES_H

#ifndef __ASSEMBLER__
#include <stdint.h>
#include <sys/commpage.h>
#ifdef KERNEL_PRIVATE
#include <mach/vm_types.h>
#endif
#endif

/*
 * This is the authoritative way to determine from x86_64 user mode what
 * implementation-specific processor features are available.
 *
 * This API only supported for Apple internal use.
 */

/* Bit definitions for emulated _cpu_capabilities: */

#define x86_64_kHasMMX                  0x00000001
#define x86_64_kHasSSE                  0x00000002
#define x86_64_kHasSSE2                 0x00000004
#define x86_64_kHasSSE3                 0x00000008
#define x86_64_kCache32                 0x00000010      /* cache line size is 32 bytes */
#define x86_64_kCache64                 0x00000020
#define x86_64_kCache128                0x00000040
#define x86_64_kFastThreadLocalStorage  0x00000080      /* TLS ptr is kept in a user-mode-readable register */
#define x86_64_kHasSupplementalSSE3             0x00000100
#define x86_64_k64Bit                   0x00000200      /* processor supports EM64T (not what mode you're running in) */
#define x86_64_kHasSSE4_1               0x00000400
#define x86_64_kHasSSE4_2               0x00000800
#define x86_64_kHasAES                  0x00001000
#define x86_64_kInOrderPipeline 0x00002000
#define x86_64_kSlow                    0x00004000      /* tsc < nanosecond */
#define x86_64_kUP                              0x00008000      /* set if (kNumCPUs == 1) */
#define x86_64_kNumCPUs                 0x00FF0000      /* number of CPUs (see _NumCPUs() below) */
#define x86_64_kNumCPUsShift    16
#define x86_64_kHasAVX1_0               0x01000000
#define x86_64_kHasRDRAND               0x02000000
#define x86_64_kHasF16C                 0x04000000
#define x86_64_kHasENFSTRG              0x08000000
#define x86_64_kHasFMA                  0x10000000
#define x86_64_kHasAVX2_0               0x20000000
#define x86_64_kHasBMI1                 0x40000000
#define x86_64_kHasBMI2                 0x80000000
/* Extending into 64-bits from here: */
#define x86_64_kHasRTM                  0x0000000100000000ULL
#define x86_64_kHasHLE                  0x0000000200000000ULL
#define x86_64_kHasRDSEED               0x0000000800000000ULL
#define x86_64_kHasADX                  0x0000000400000000ULL
#define x86_64_kHasMPX                  0x0000001000000000ULL
#define x86_64_kHasSGX                  0x0000002000000000ULL
#if !defined(RC_HIDE_XNU_J137)
#define x86_64_kHasAVX512F              0x0000004000000000ULL
#define x86_64_kHasAVX512CD             0x0000008000000000ULL
#define x86_64_kHasAVX512DQ             0x0000010000000000ULL
#define x86_64_kHasAVX512BW             0x0000020000000000ULL
#define x86_64_kHasAVX512IFMA   0x0000040000000000ULL
#define x86_64_kHasAVX512VBMI   0x0000080000000000ULL
#define x86_64_kHasAVX512VL             0x0000100000000000ULL
#endif /* not RC_HIDE_XNU_J137 */

#define x86_64_kIsTranslated    0x4000000000000000ULL   // isTranslated
/* Cambria specific. The address space page shift. */
#define x86_64_kVmPageShift     0xFFB

/*
 * The effectively cast-in-stone x86_64 comm page address that we
 * simulate for compatibility purposes.
 */

#define X86_64_COMM_PAGE_BASE_ADDRESS           (0x7fffffe00000ULL)
#define X86_64_COMM_PAGE_AREA_LENGTH            4096
#define X86_64_COMM_PAGE_VERSION                        14
#define X86_64_MP_SPIN_TRIES                    1000

#ifdef KERNEL_PRIVATE
extern vm_address_t x86_64_sharedpage_rw_addr;
extern uint64_t _get_x86_64_cpu_capabilities(void);
#endif

typedef struct {
/*  0 */ uint8_t signature[16];
/* 10 */ uint64_t cpu_capabilities64;
/* 18 */ uint8_t _unused[6];
/* 1e */ uint16_t version;
/* 20 */ uint32_t cpu_capabilities;
/* 24 */ uint8_t _unused0[2];
/* 26 */ uint16_t cache_linesize;
/* 28 */ volatile uint32_t sched_gen;
/* 2c */ volatile uint32_t memory_pressure;
/* 30 */ volatile uint32_t spin_count;
/* 34 */ volatile uint8_t active_cpus;
/* 35 */ uint8_t physical_cpus;
/* 36 */ uint8_t logical_cpus;
/* 37 */ uint8_t _unused1[1];
/* 38 */ uint64_t memory_size;
/* 40 */ uint32_t cpufamily;
/* 44 */ volatile uint32_t kdebug_enable;
/* 48 */ volatile uint32_t atm_diagnostic_config;
/* 4C */ uint8_t cp_dtrace_dof_enabled;
/* 4D */ uint8_t cp_kernel_page_shift; /* _COMM_PAGE_VERSION >= 14 */
/* 4E */ uint8_t cp_user_page_shift; /* _COMM_PAGE_VERSION >= 14 */
/* 4F */ uint8_t _unused2;
	volatile struct {
/* 50 */ uint64_t nt_tsc_base;
/* 58 */ uint32_t nt_scale;
/* 5c */ uint32_t nt_shift;
/* 60 */ uint64_t nt_ns_base;
/* 68 */ uint32_t nt_generation;
/* 6c */ uint32_t gtod_generation;
/* 70 */ uint64_t gtod_ns_base;
/* 78 */ uint64_t gtod_sec_base;
	} time_data;
	volatile union {
		struct {
/* 80 */ uint64_t time;
/* 88 */ uint64_t time_supported;
		} _;
		uint8_t _fill[64];
	} approx;
/* c0 */ volatile uint64_t cont_timebase;
/* c8 */ volatile uint64_t boottime_usec;
	new_commpage_timeofday_data_t new_time_data;
/*			{								*/
/* d0			uint64_t TimeStamp_tick;	*/
/* d8			uint64_t TimeStamp_sec;		*/
/* e0			uint64_t TimeStamp_frac;	*/
/* e8			uint64_t Ticks_scale;		*/
/* f0			uint64_t Ticks_per_sec;		*/
/*			}								*/

/* f8 */ uint64_t unused;
/* 100 */ uint64_t dyld_system_flags;

/* 108 */ uint8_t unused2[3800];
/* 0xFE0 */ uint8_t cp_aprr_shadow_supported;
/* 0xFE1 */ uint8_t unused3[7];
/* 0xFE8 */ uint64_t cp_aprr_shadow_jit_rw;
/* 0xFF0*/ uint64_t cp_aprr_shadow_jit_rx;
/* 0xFF8 */ uint32_t unused4;
/* ffc */ uint32_t arm_cpufamily;
} x86_64_commpage_t;

#endif /* _ARM_CPU_X86_64_CAPABILITIES_H */
#endif /* PRIVATE */
