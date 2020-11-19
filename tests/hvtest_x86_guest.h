#pragma once

#include <os/base.h>
#include <stdint.h>

extern void save_restore_regs_entry(uint64_t arg) OS_NORETURN;
extern void save_restore_debug_regs_entry(uint64_t arg) OS_NORETURN;
extern void simple_real_mode_vcpu_entry(uint64_t arg) OS_NORETURN;
extern void simple_protected_mode_vcpu_entry(uint64_t arg) OS_NORETURN;
extern void simple_long_mode_vcpu_entry(uint64_t arg) OS_NORETURN;
extern void smp_vcpu_entry(uint64_t) OS_NORETURN;
extern void radar61961809_entry(uint64_t) OS_NORETURN;
extern void radar61961809_prepare(uint64_t) OS_NORETURN;
extern void radar61961809_loop64(uint64_t) OS_NORETURN;
extern void radar60691363_entry(uint64_t) OS_NORETURN;

#define MSR_IA32_STAR           0xc0000081
#define MSR_IA32_LSTAR          0xc0000082
#define MSR_IA32_CSTAR          0xc0000083
#define MSR_IA32_FMASK          0xc0000084
#define MSR_IA32_KERNEL_GS_BASE 0xc0000102
#define MSR_IA32_TSC            0x00000010
#define MSR_IA32_TSC_AUX        0xc0000103

#define MSR_IA32_SYSENTER_CS    0x00000174
#define MSR_IA32_SYSENTER_ESP   0x00000175
#define MSR_IA32_SYSENTER_EIP   0x00000176
#define MSR_IA32_FS_BASE        0xc0000100
#define MSR_IA32_GS_BASE        0xc0000101

extern void native_msr_vcpu_entry(uint64_t) OS_NORETURN;
