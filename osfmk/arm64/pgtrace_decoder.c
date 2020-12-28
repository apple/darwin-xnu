/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

#if CONFIG_PGTRACE
#include <kern/debug.h>
#include <kern/clock.h>
#include <pexpert/pexpert.h>
#include <arm/pmap.h>
#include "pgtrace_decoder.h"

//-------------------------------------------------------------------
// Macros
//
#define DBG     1
#if DBG == 1
#define INLINE  __attribute__((noinline))
#else
#define INLINE  inline
#endif

#define BITS(v, msb, lsb)    ((v) << (31-msb) >> (31-msb) >> (lsb))
#define READ_GPR_X(ss, n, v) { \
    if (__builtin_expect(n < 31, 1)) (v) = (ss)->ss_64.x[(n)]; \
    else if (n == 31) (v) = 0; \
    else { panic("Invalid GPR x%d", n); __builtin_unreachable(); } \
}
#define READ_GPR_W(ss, n, v) { \
    if (__builtin_expect(n < 31, 1)) (v) = *(uint32_t*)&((ss)->ss_64.x[(n)]); \
    else if (n == 31) (v) = 0; \
    else { panic("Invalid GPR w%d", n); __builtin_unreachable(); } \
}
#define WRITE_GPR_X(ss, n, v) { \
    if (__builtin_expect(n < 31, 1)) (ss)->ss_64.x[(n)] = (v); \
    else if (n == 31) {} \
    else { panic("Invalid GPR x%d", n); __builtin_unreachable(); } \
}
#define WRITE_GPR_W(ss, n, v) { \
    if (__builtin_expect(n < 31, 1)) *(uint32_t*)&((ss)->ss_64.x[(n)]) = (v); \
    else if (n == 31) {} \
    else { panic("Invalid GPR w%d", n); __builtin_unreachable(); } \
}
#define SIGN_EXTEND_64(val, width)  (((int64_t)(val) << (64 - (width)) >> (64 - (width))))
#define ZERO_EXTEND_64(val, width)  (((uint64_t)(val) << (64 - (width))) >> (64 - (width)))

//-------------------------------------------------------------------
// Types
//
typedef int (*run_t)(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);

typedef struct {
	vm_offset_t addr;
	uint64_t    bytes;
} instruction_info_t;

typedef bool (*get_info_t)(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);

typedef struct {
	uint32_t mask;
	uint32_t value;
	run_t run;
	get_info_t get_info;
} type_entry_t;

//-------------------------------------------------------------------
// Statics
//
static int run_simd(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c335(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c336(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c337(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c338(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c339(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c3310(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c3311(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c3312(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c3313(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c3314(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c3315(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static int run_c3316(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res);
static bool get_info_simd(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c335(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c336(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c337(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c338(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c339(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c3310(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c3311(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c3312(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c3313(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c3314(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c3315(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);
static bool get_info_c3316(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info);

// Table from ARM DDI 0487A.a C3.3
static type_entry_t typetbl[] = {
	{ 0x3f000000, 0x08000000, run_c336, get_info_c336 }, // Load/store exclusive
	{ 0x3b000000, 0x18000000, run_c335, get_info_c335 }, // Load register (literal)
	{ 0x3b800000, 0x28000000, run_c337, get_info_c337 }, // Load/store no-allocate pair (offset)
	{ 0x3b800000, 0x28800000, run_c3315, get_info_c3315 }, // Load/store register pair (post-indexed)
	{ 0x3b800000, 0x29000000, run_c3314, get_info_c3314 }, // Load/store register pair (offset)
	{ 0x3b800000, 0x29800000, run_c3316, get_info_c3316 }, // Load/store register pair (pre-indexed)
	{ 0x3b200c00, 0x38000000, run_c3312, get_info_c3312 }, // Load/store register (unscaled immediate)
	{ 0x3b200c00, 0x38000400, run_c338, get_info_c338 }, // Load/store register (immediate post-indexed)
	{ 0x3b200c00, 0x38000800, run_c3311, get_info_c3311 }, // Load/store register (unprivileged)
	{ 0x3b200c00, 0x38000c00, run_c339, get_info_c339 }, // Load/store register (immediate pre-indexed)
	{ 0x3b200c00, 0x38200800, run_c3310, get_info_c3310 }, // Load/store register (register offset)
	{ 0x3b000000, 0x39000000, run_c3313, get_info_c3313 }, // Load/store register (unsigned immediate)

	{ 0xbfbf0000, 0x0c000000, run_simd, get_info_simd }, // AdvSIMD load/store multiple structures
	{ 0xbfa00000, 0x0c800000, run_simd, get_info_simd }, // AdvSIMD load/store multiple structures (post-indexed)
	{ 0xbf980000, 0x0d000000, run_simd, get_info_simd }, // AdvSIMD load/store single structure
	{ 0xbf800000, 0x0d800000, run_simd, get_info_simd } // AdvSIMD load/store single structure (post-indexed)
};

static pgtrace_stats_t stats;

INLINE static void
do_str(uint8_t size, uint8_t Rt, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t wt;
	uint64_t xt;

	res->rr_rw = PGTRACE_RW_STORE;

	if (size == 8) {
		READ_GPR_X(ss, Rt, xt);
		res->rr_addrdata[0].ad_data = xt;
	} else {
		READ_GPR_W(ss, Rt, wt);
		res->rr_addrdata[0].ad_data = wt;
	}

	if (size == 1) {
		__asm__ volatile ("strb %w[wt], [%[va]]\n" :: [wt] "r"(wt), [va] "r"(va));
	} else if (size == 2) {
		__asm__ volatile ("strh %w[wt], [%[va]]\n" :: [wt] "r"(wt), [va] "r"(va));
	} else if (size == 4) {
		__asm__ volatile ("str %w[wt], [%[va]]\n" :: [wt] "r"(wt), [va] "r"(va));
	} else if (size == 8) {
		__asm__ volatile ("str %x[xt], [%[va]]\n" :: [xt] "r"(xt), [va] "r"(va));
	} else {
		panic("%s Invalid size %d\n", __func__, size);
	}

	stats.stat_decoder.sd_str++;
}

INLINE static void
do_ldr(uint8_t size, uint8_t Rt, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t wt;
	uint64_t xt;

	res->rr_rw = PGTRACE_RW_LOAD;

	if (size == 1) {
		__asm__ volatile ("ldrb %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
	} else if (size == 2) {
		__asm__ volatile ("ldrh %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
	} else if (size == 4) {
		__asm__ volatile ("ldr %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
	} else if (size == 8) {
		__asm__ volatile ("ldr %x[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
	} else {
		panic("%s Invalid size %d\n", __func__, size);
	}

	if (size == 8) {
		WRITE_GPR_X(ss, Rt, xt);
		res->rr_addrdata[0].ad_data = xt;
	} else {
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_addrdata[0].ad_data = wt;
	}

	stats.stat_decoder.sd_ldr++;
}

INLINE static void
do_stp(uint8_t size, uint8_t Rt, uint8_t Rt2, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t wt1, wt2;
	uint64_t xt1, xt2;

	if (size == 4) {
		READ_GPR_W(ss, Rt, wt1);
		READ_GPR_W(ss, Rt2, wt2);
		__asm__ volatile ("stp %w[wt1], %w[wt2], [%[va]]\n" :: [wt1] "r"(wt1), [wt2] "r"(wt2), [va] "r"(va));
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[1].ad_addr = va + sizeof(wt1);
		res->rr_addrdata[0].ad_data = wt1;
		res->rr_addrdata[1].ad_data = wt2;
	} else if (size == 8) {
		READ_GPR_X(ss, Rt, xt1);
		READ_GPR_X(ss, Rt2, xt2);
		__asm__ volatile ("stp %x[xt1], %x[xt2], [%[va]]\n" :: [xt1] "r"(xt1), [xt2] "r"(xt2), [va] "r"(va));
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[1].ad_addr = va + sizeof(xt1);
		res->rr_addrdata[0].ad_data = xt1;
		res->rr_addrdata[1].ad_data = xt2;
	} else {
		panic("%s Invalid size %d\n", __func__, size);
	}

	stats.stat_decoder.sd_stp++;
}

INLINE static void
do_ldp(uint8_t size, uint8_t Rt, uint8_t Rt2, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t wt1, wt2;
	uint64_t xt1, xt2;

	if (size == 4) {
		__asm__ volatile ("ldp %w[wt1], %w[wt2], [%[va]]\n" : [wt1] "=r"(wt1), [wt2] "=r"(wt2) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt1);
		WRITE_GPR_W(ss, Rt2, wt2);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[1].ad_addr = va + sizeof(wt1);
		res->rr_addrdata[0].ad_data = wt1;
		res->rr_addrdata[1].ad_data = wt2;
	} else if (size == 8) {
		__asm__ volatile ("ldp %x[xt1], %x[xt2], [%[va]]\n" : [xt1] "=r"(xt1), [xt2] "=r"(xt2) : [va] "r"(va));
		WRITE_GPR_X(ss, Rt, xt1);
		WRITE_GPR_X(ss, Rt2, xt2);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[1].ad_addr = va + sizeof(xt1);
		res->rr_addrdata[0].ad_data = xt1;
		res->rr_addrdata[1].ad_data = xt2;
	} else {
		panic("%s Invalid size %d\n", __func__, size);
	}

	stats.stat_decoder.sd_ldp++;
}

INLINE static void
do_ldpsw(uint8_t Rt, uint8_t Rt2, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint64_t xt1, xt2;

	__asm__ volatile ("ldpsw %x[xt1], %x[xt2], [%[va]]\n" : [xt1] "=r"(xt1), [xt2] "=r"(xt2) : [va] "r"(va));
	WRITE_GPR_X(ss, Rt, xt1);
	WRITE_GPR_X(ss, Rt2, xt2);
	res->rr_rw = PGTRACE_RW_LOAD;
	res->rr_addrdata[1].ad_addr = va + sizeof(uint32_t);
	res->rr_addrdata[0].ad_data = xt1;
	res->rr_addrdata[1].ad_data = xt2;

	stats.stat_decoder.sd_ldpsw++;
}

INLINE static void
do_ldrs(uint8_t size, uint8_t extsize, uint8_t Rt, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t wt;
	uint64_t xt;

	res->rr_rw = PGTRACE_RW_LOAD;

	if (size == 1 && extsize == 4) {
		__asm__ volatile ("ldrsb %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
	} else if (size == 1 && extsize == 8) {
		__asm__ volatile ("ldrsb %x[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
	} else if (size == 2 && extsize == 4) {
		__asm__ volatile ("ldrsh %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
	} else if (size == 2 && extsize == 8) {
		__asm__ volatile ("ldrsh %x[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
	} else if (size == 4 && extsize == 8) {
		__asm__ volatile ("ldrsw %x[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
	} else {
		panic("%s Invalid size %d extsize=%d\n", __func__, size, extsize);
	}

	if (extsize == 8) {
		WRITE_GPR_X(ss, Rt, xt);
		res->rr_addrdata[0].ad_data = xt;
	} else {
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_addrdata[0].ad_data = wt;
	}

	stats.stat_decoder.sd_ldrs++;
}

INLINE static void
do_ldtrs(uint8_t size, uint8_t extsize, uint8_t Rt, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t wt;
	uint64_t xt;

	res->rr_rw = PGTRACE_RW_LOAD;

	if (size == 1 && extsize == 4) {
		__asm__ volatile ("ldtrsb %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
	} else if (size == 1 && extsize == 8) {
		__asm__ volatile ("ldtrsb %x[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
	} else if (size == 2 && extsize == 4) {
		__asm__ volatile ("ldtrsh %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
	} else if (size == 2 && extsize == 8) {
		__asm__ volatile ("ldtrsh %x[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
	} else if (size == 4 && extsize == 8) {
		__asm__ volatile ("ldtrsw %x[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
	} else {
		panic("%s Invalid size %d extsize=%d\n", __func__, size, extsize);
	}

	if (extsize == 8) {
		WRITE_GPR_X(ss, Rt, xt);
		res->rr_addrdata[0].ad_data = xt;
	} else {
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_addrdata[0].ad_data = wt;
	}

	stats.stat_decoder.sd_ldtrs++;
}

INLINE static void
do_ldtr(uint8_t size, uint8_t Rt, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t wt;
	uint64_t xt;

	res->rr_rw = PGTRACE_RW_LOAD;

	if (size == 1) {
		__asm__ volatile ("ldtrb %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
	} else if (size == 2) {
		__asm__ volatile ("ldtrh %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
	} else if (size == 4) {
		__asm__ volatile ("ldtr %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
	} else if (size == 8) {
		__asm__ volatile ("ldtr %x[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
	} else {
		panic("%s Invalid size %d\n", __func__, size);
	}

	if (size == 8) {
		WRITE_GPR_X(ss, Rt, xt);
		res->rr_addrdata[0].ad_data = xt;
	} else {
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_addrdata[0].ad_data = wt;
	}

	stats.stat_decoder.sd_ldtr++;
}

INLINE static void
do_sttr(uint8_t size, uint8_t Rt, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t wt;
	uint64_t xt;

	res->rr_rw = PGTRACE_RW_STORE;

	if (size == 8) {
		READ_GPR_X(ss, Rt, xt);
		res->rr_addrdata[0].ad_data = xt;
	} else {
		READ_GPR_W(ss, Rt, wt);
		res->rr_addrdata[0].ad_data = wt;
	}

	if (size == 1) {
		__asm__ volatile ("sttrb %w[wt], [%[va]]\n" :: [wt] "r"(wt), [va] "r"(va));
	} else if (size == 2) {
		__asm__ volatile ("sttrh %w[wt], [%[va]]\n" :: [wt] "r"(wt), [va] "r"(va));
	} else if (size == 4) {
		__asm__ volatile ("sttr %w[wt], [%[va]]\n" :: [wt] "r"(wt), [va] "r"(va));
	} else if (size == 8) {
		__asm__ volatile ("sttr %x[xt], [%[va]]\n" :: [xt] "r"(xt), [va] "r"(va));
	} else {
		panic("%s Invalid size %d\n", __func__, size);
	}

	stats.stat_decoder.sd_sttr++;
}

INLINE static void
do_prfm(uint8_t Rt, vm_offset_t va, pgtrace_run_result_t *res)
{
	if (Rt == 0) {
		__asm__ volatile ("prfm pldl1keep, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 1) {
		__asm__ volatile ("prfm pldl1strm, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 2) {
		__asm__ volatile ("prfm pldl2keep, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 3) {
		__asm__ volatile ("prfm pldl2strm, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 4) {
		__asm__ volatile ("prfm pldl3keep, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 5) {
		__asm__ volatile ("prfm pldl3strm, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 6) {
		__asm__ volatile ("prfm #6, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 7) {
		__asm__ volatile ("prfm #7, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 8) {
		__asm__ volatile ("prfm #8, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 9) {
		__asm__ volatile ("prfm #9, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 10) {
		__asm__ volatile ("prfm #10, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 11) {
		__asm__ volatile ("prfm #11, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 12) {
		__asm__ volatile ("prfm #12, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 13) {
		__asm__ volatile ("prfm #13, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 14) {
		__asm__ volatile ("prfm #14, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 15) {
		__asm__ volatile ("prfm #15, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 16) {
		__asm__ volatile ("prfm pstl1keep, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 17) {
		__asm__ volatile ("prfm pstl1strm, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 18) {
		__asm__ volatile ("prfm pstl2keep, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 19) {
		__asm__ volatile ("prfm pstl2strm, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 20) {
		__asm__ volatile ("prfm pstl3keep, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 21) {
		__asm__ volatile ("prfm pstl3strm, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 22) {
		__asm__ volatile ("prfm #22, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 23) {
		__asm__ volatile ("prfm #23, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 24) {
		__asm__ volatile ("prfm #24, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 25) {
		__asm__ volatile ("prfm #25, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 26) {
		__asm__ volatile ("prfm #26, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 27) {
		__asm__ volatile ("prfm #27, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 28) {
		__asm__ volatile ("prfm #28, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 29) {
		__asm__ volatile ("prfm #29, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 30) {
		__asm__ volatile ("prfm #30, [%[va]]\n" : : [va] "r"(va));
	} else if (Rt == 31) {
		__asm__ volatile ("prfm #31, [%[va]]\n" : : [va] "r"(va));
	} else {
		panic("%s Invalid Rt %d\n", __func__, Rt);
	}

	res->rr_num = 0;
	res->rr_rw = PGTRACE_RW_PREFETCH;

	stats.stat_decoder.sd_prfm++;
}

#define CANNOTDECODE(msg, inst) do {\
    panic("%s: " msg " inst=%x not supported yet\n", __func__, inst);\
} while (0)

static int
run_simd(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
#pragma unused(pa,va,ss,res)
	CANNOTDECODE("simd", inst);
	return 0;
}

static int
run_c335(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t opc = BITS(inst, 31, 30),
	    v = BITS(inst, 26, 26),
	    Rt = BITS(inst, 4, 0);
	uint8_t fields = (opc << 1) | v;

	res->rr_num = 1;
	res->rr_addrdata[0].ad_addr = pa;

	if (fields == 0) {
		do_ldr(4, Rt, va, ss, res);
	} else if ((fields == 1) ||
	    (fields == 3) ||
	    (fields == 5)) {
		CANNOTDECODE("simd", inst);
	} else if (fields == 2) {
		do_ldr(8, Rt, va, ss, res);
	} else if (fields == 4) {
		do_ldrs(4, 8, Rt, va, ss, res);
	} else if (fields == 6) {
		do_prfm(Rt, va, res);
	} else {
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c335++;

	return 0;
}

static int
run_c336(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t ws, wt, wt1, wt2;
	uint64_t xt, xt1, xt2;
	uint32_t size = BITS(inst, 31, 30),
	    o2 = BITS(inst, 23, 23),
	    L = BITS(inst, 22, 22),
	    o1 = BITS(inst, 21, 21),
	    Rs = BITS(inst, 20, 16),
	    o0 = BITS(inst, 15, 15),
	    Rt2 = BITS(inst, 14, 10),
	    Rt = BITS(inst, 4, 0);
	uint8_t fields = (size << 4) | (o2 << 3) | (L << 2) | (o1 << 1) | o0;

	kprintf("%s Load/store exclusive on device memory???n", __func__);

	res->rr_num = 1;
	res->rr_addrdata[0].ad_addr = pa;

	switch (fields) {
	case 0:
		READ_GPR_W(ss, Rt, wt);
		__asm__ volatile ("stxrb %w[ws], %w[wt], [%[va]]\n" : [ws] "=r"(ws) : [wt] "r"(wt), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 1:
		READ_GPR_W(ss, Rt, wt);
		__asm__ volatile ("stlxrb %w[ws], %w[wt], [%[va]]\n" : [ws] "=r"(ws) : [wt] "r"(wt), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 4:
		__asm__ volatile ("ldxrb %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 5:
		__asm__ volatile ("ldaxrb %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 9:
		READ_GPR_W(ss, Rt, wt);
		__asm__ volatile ("stlrb %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0xd:
		__asm__ volatile ("ldarb %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x10:
		READ_GPR_W(ss, Rt, wt);
		__asm__ volatile ("stxrh %w[ws], %w[wt], [%[va]]\n" : [ws] "=r"(ws) : [wt] "r"(wt), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x11:
		READ_GPR_W(ss, Rt, wt);
		__asm__ volatile ("stlxrh %w[ws], %w[wt], [%[va]]\n" : [ws] "=r"(ws) : [wt] "r"(wt), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x14:
		__asm__ volatile ("ldxrh %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x15:
		__asm__ volatile ("ldaxrh %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x19:
		READ_GPR_W(ss, Rt, wt);
		__asm__ volatile ("stlrh %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x1d:
		__asm__ volatile ("ldarh %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x20:
		READ_GPR_W(ss, Rt, wt);
		__asm__ volatile ("stxr %w[ws], %w[wt], [%[va]]\n" : [ws] "=r"(ws) : [wt] "r"(wt), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x21:
		READ_GPR_W(ss, Rt, wt);
		__asm__ volatile ("stlxr %w[ws], %w[wt], [%[va]]\n" : [ws] "=r"(ws) : [wt] "r"(wt), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x22:
		READ_GPR_W(ss, Rt, wt1);
		READ_GPR_W(ss, Rt2, wt2);
		__asm__ volatile ("stxp %w[ws], %w[wt1], %w[wt2], [%[va]]\n" : [ws] "=r"(ws) : [wt1] "r"(wt1), [wt2] "r"(wt2), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = va;
		res->rr_addrdata[1].ad_addr = va + sizeof(wt1);
		res->rr_addrdata[0].ad_data = wt1;
		res->rr_addrdata[1].ad_data = wt2;
		break;
	case 0x23:
		READ_GPR_W(ss, Rt, wt1);
		READ_GPR_W(ss, Rt2, wt2);
		__asm__ volatile ("stlxp %w[ws], %w[wt1], %w[wt2], [%[va]]\n" : [ws] "=r"(ws) : [wt1] "r"(wt1), [wt2] "r"(wt2), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = va;
		res->rr_addrdata[1].ad_addr = va + sizeof(wt1);
		res->rr_addrdata[0].ad_data = wt1;
		res->rr_addrdata[1].ad_data = wt2;
		break;
	case 0x24:
		__asm__ volatile ("ldxr %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x25:
		__asm__ volatile ("ldaxr %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x26:
		__asm__ volatile ("ldxp %w[wt1], %w[wt2], [%[va]]\n" : [wt1] "=r"(wt1), [wt2] "=r"(wt2) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt1);
		WRITE_GPR_W(ss, Rt2, wt2);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = va;
		res->rr_addrdata[1].ad_addr = va + sizeof(wt1);
		res->rr_addrdata[0].ad_data = wt1;
		res->rr_addrdata[1].ad_data = wt2;
		break;
	case 0x27:
		__asm__ volatile ("ldaxp %w[wt1], %w[wt2], [%[va]]\n" : [wt1] "=r"(wt1), [wt2] "=r"(wt2) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt1);
		WRITE_GPR_W(ss, Rt2, wt2);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = va;
		res->rr_addrdata[1].ad_addr = va + sizeof(wt1);
		res->rr_addrdata[0].ad_data = wt1;
		res->rr_addrdata[1].ad_data = wt2;
		break;
	case 0x29:
		READ_GPR_W(ss, Rt, wt);
		__asm__ volatile ("stlr %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x2d:
		__asm__ volatile ("ldar %w[wt], [%[va]]\n" : [wt] "=r"(wt) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = wt;
		break;
	case 0x30:
		READ_GPR_X(ss, Rt, xt);
		__asm__ volatile ("stxr %w[ws], %[xt], [%[va]]\n" : [ws] "=r"(ws) : [xt] "r"(xt), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = xt;
		break;
	case 0x31:
		READ_GPR_X(ss, Rt, xt);
		__asm__ volatile ("stlxr %w[ws], %[xt], [%[va]]\n" : [ws] "=r"(ws) : [xt] "r"(xt), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = xt;
		break;
	case 0x32:
		READ_GPR_X(ss, Rt, xt1);
		READ_GPR_X(ss, Rt2, xt2);
		__asm__ volatile ("stxp %w[ws], %[xt1], %[xt2], [%[va]]\n" : [ws] "=r"(ws) : [xt1] "r"(xt1), [xt2] "r"(xt2), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = va;
		res->rr_addrdata[1].ad_addr = va + sizeof(xt1);
		res->rr_addrdata[0].ad_data = xt1;
		res->rr_addrdata[1].ad_data = xt2;
		break;
	case 0x33:
		READ_GPR_X(ss, Rt, xt1);
		READ_GPR_X(ss, Rt2, xt2);
		__asm__ volatile ("stlxp %w[ws], %[xt1], %[xt2], [%[va]]\n" : [ws] "=r"(ws) : [xt1] "r"(xt1), [xt2] "r"(xt2), [va] "r"(va));
		WRITE_GPR_W(ss, Rs, ws);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = va;
		res->rr_addrdata[1].ad_addr = va + sizeof(xt1);
		res->rr_addrdata[0].ad_data = xt1;
		res->rr_addrdata[1].ad_data = xt2;
		break;
	case 0x34:
		__asm__ volatile ("ldxr %[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
		WRITE_GPR_X(ss, Rt, xt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = xt;
		break;
	case 0x35:
		__asm__ volatile ("ldaxr %[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
		WRITE_GPR_X(ss, Rt, xt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = xt;
		break;
	case 0x36:
		__asm__ volatile ("ldxp %[xt1], %[xt2], [%[va]]\n" : [xt1] "=r"(xt1), [xt2] "=r"(xt2) : [va] "r"(va));
		WRITE_GPR_X(ss, Rt, xt1);
		WRITE_GPR_X(ss, Rt2, xt2);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = va;
		res->rr_addrdata[1].ad_addr = va + sizeof(xt1);
		res->rr_addrdata[0].ad_data = xt1;
		res->rr_addrdata[0].ad_data = xt2;
		break;
	case 0x37:
		__asm__ volatile ("ldaxp %[xt1], %[xt2], [%[va]]\n" : [xt1] "=r"(xt1), [xt2] "=r"(xt2) : [va] "r"(va));
		WRITE_GPR_X(ss, Rt, xt1);
		WRITE_GPR_X(ss, Rt2, xt2);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = va;
		res->rr_addrdata[1].ad_addr = va + sizeof(xt1);
		res->rr_addrdata[0].ad_data = xt1;
		res->rr_addrdata[0].ad_data = xt2;
		break;
	case 0x39:
		READ_GPR_X(ss, Rt, xt);
		__asm__ volatile ("stlr %[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_addrdata[0].ad_data = xt;
		break;
	case 0x3d:
		__asm__ volatile ("ldar %[xt], [%[va]]\n" : [xt] "=r"(xt) : [va] "r"(va));
		WRITE_GPR_X(ss, Rt, xt);
		res->rr_rw = PGTRACE_RW_LOAD;
		res->rr_addrdata[0].ad_data = xt;
		break;
	default:
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c336++;

	return 0;
}

static int
run_c337(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t wt1, wt2;
	uint64_t xt1, xt2;
	uint32_t opc = BITS(inst, 31, 30),
	    V = BITS(inst, 26, 26),
	    L = BITS(inst, 22, 22),
	    Rt = BITS(inst, 4, 0),
	    Rt2 = BITS(inst, 14, 10);
	uint8_t fields = (opc << 2) | (V << 1) | L;

	switch (fields) {
	case 0:
		READ_GPR_W(ss, Rt, wt1);
		READ_GPR_W(ss, Rt2, wt2);
		__asm__ volatile ("stnp %w[wt1], %w[wt2], [%[va]]\n" :: [wt1] "r"(wt1), [wt2] "r"(wt2), [va] "r"(va));
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = pa;
		res->rr_addrdata[1].ad_addr = pa + sizeof(wt1);
		res->rr_addrdata[0].ad_data = wt1;
		res->rr_addrdata[1].ad_data = wt2;
		break;
	case 1:
		__asm__ volatile ("ldnp %w[wt1], %w[wt2], [%[va]]\n" : [wt1] "=r"(wt1), [wt2] "=r"(wt2) : [va] "r"(va));
		WRITE_GPR_W(ss, Rt, wt1);
		WRITE_GPR_W(ss, Rt2, wt2);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = pa;
		res->rr_addrdata[1].ad_addr = pa + sizeof(wt1);
		res->rr_addrdata[0].ad_data = wt1;
		res->rr_addrdata[1].ad_data = wt2;
		break;
	case 2:
	case 3:
	case 6:
	case 7:
	case 10:
	case 11:
		CANNOTDECODE("simd", inst);
	case 8:
		READ_GPR_X(ss, Rt, xt1);
		READ_GPR_X(ss, Rt2, xt2);
		__asm__ volatile ("stnp %x[xt1], %x[xt2], [%[va]]\n" :: [xt1] "r"(xt1), [xt2] "r"(xt2), [va] "r"(va));
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = pa;
		res->rr_addrdata[1].ad_addr = pa + sizeof(xt1);
		res->rr_addrdata[0].ad_data = xt1;
		res->rr_addrdata[1].ad_data = xt2;
		break;
	case 9:
		__asm__ volatile ("ldnp %x[xt1], %x[xt2], [%[va]]\n" : [xt1] "=r"(xt1), [xt2] "=r"(xt2) : [va] "r"(va));
		WRITE_GPR_X(ss, Rt, xt1);
		WRITE_GPR_X(ss, Rt2, xt2);
		res->rr_rw = PGTRACE_RW_STORE;
		res->rr_num = 2;
		res->rr_addrdata[0].ad_addr = pa;
		res->rr_addrdata[1].ad_addr = pa + sizeof(xt1);
		res->rr_addrdata[0].ad_data = xt1;
		res->rr_addrdata[1].ad_data = xt2;
		break;
	default:
		CANNOTDECODE("simd", inst);
	}

	stats.stat_decoder.sd_c337++;

	return 0;
}

static int
run_c338(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t size = BITS(inst, 31, 30),
	    V = BITS(inst, 26, 26),
	    opc = BITS(inst, 23, 22),
	    Rt = BITS(inst, 4, 0);
	uint8_t fields = (size << 3) | (V << 2) | opc;

	res->rr_num = 1;
	res->rr_addrdata[0].ad_addr = pa;

	if (fields == 0) {
		do_str(1, Rt, va, ss, res);
	} else if (fields == 1) {
		do_ldr(1, Rt, va, ss, res);
	} else if (fields == 2) {
		do_ldrs(1, 8, Rt, va, ss, res);
	} else if (fields == 3) {
		do_ldrs(1, 4, Rt, va, ss, res);
	} else if ((fields == 4) ||
	    (fields == 5) ||
	    (fields == 6) ||
	    (fields == 7) ||
	    (fields == 12) ||
	    (fields == 13) ||
	    (fields == 0x14) ||
	    (fields == 0x15) ||
	    (fields == 0x1c) ||
	    (fields == 0x1d)) {
		CANNOTDECODE("simd", inst);
	} else if (fields == 8) {
		do_str(2, Rt, va, ss, res);
	} else if (fields == 9) {
		do_ldr(2, Rt, va, ss, res);
	} else if (fields == 10) {
		do_ldrs(2, 8, Rt, va, ss, res);
	} else if (fields == 11) {
		do_ldrs(2, 4, Rt, va, ss, res);
	} else if (fields == 0x10) {
		do_str(4, Rt, va, ss, res);
	} else if (fields == 0x11) {
		do_ldr(4, Rt, va, ss, res);
	} else if (fields == 0x12) {
		do_ldrs(4, 8, Rt, va, ss, res);
	} else if (fields == 0x18) {
		do_str(8, Rt, va, ss, res);
	} else if (fields == 0x19) {
		do_ldr(8, Rt, va, ss, res);
	} else {
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c338++;

	return 0;
}

static int
run_c339(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t size = BITS(inst, 31, 30),
	    V = BITS(inst, 26, 26),
	    opc = BITS(inst, 23, 22),
	    Rt = BITS(inst, 4, 0);
	uint8_t fields = (size << 3) | (V << 2) | opc;

	res->rr_num = 1;
	res->rr_addrdata[0].ad_addr = pa;

	if (fields == 0) {
		do_str(1, Rt, va, ss, res);
	} else if (fields == 1) {
		do_ldr(1, Rt, va, ss, res);
	} else if (fields == 2) {
		do_ldrs(1, 8, Rt, va, ss, res);
	} else if (fields == 3) {
		do_ldrs(1, 4, Rt, va, ss, res);
	} else if ((fields == 4) ||
	    (fields == 5) ||
	    (fields == 6) ||
	    (fields == 7) ||
	    (fields == 12) ||
	    (fields == 13) ||
	    (fields == 0x14) ||
	    (fields == 0x15) ||
	    (fields == 0x1c) ||
	    (fields == 0x1d)) {
		CANNOTDECODE("simd", inst);
	} else if (fields == 8) {
		do_str(2, Rt, va, ss, res);
	} else if (fields == 9) {
		do_ldr(2, Rt, va, ss, res);
	} else if (fields == 10) {
		do_ldrs(2, 8, Rt, va, ss, res);
	} else if (fields == 11) {
		do_ldrs(2, 4, Rt, va, ss, res);
	} else if (fields == 0x10) {
		do_str(4, Rt, va, ss, res);
	} else if (fields == 0x11) {
		do_ldr(4, Rt, va, ss, res);
	} else if (fields == 0x12) {
		do_ldrs(4, 8, Rt, va, ss, res);
	} else if (fields == 0x18) {
		do_str(8, Rt, va, ss, res);
	} else if (fields == 0x19) {
		do_ldr(8, Rt, va, ss, res);
	} else {
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c339++;

	return 0;
}

static int
run_c3310(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t size = BITS(inst, 31, 30),
	    V = BITS(inst, 26, 26),
	    opc = BITS(inst, 23, 22),
	    Rt = BITS(inst, 4, 0);
	uint8_t fields = (size << 3) | (V << 2) | opc;

	res->rr_num = 1;
	res->rr_addrdata[0].ad_addr = pa;

	if (fields == 0) {
		do_str(1, Rt, va, ss, res);
	} else if (fields == 1) {
		do_ldr(1, Rt, va, ss, res);
	} else if (fields == 2) {
		do_ldrs(1, 8, Rt, va, ss, res);
	} else if (fields == 3) {
		do_ldrs(1, 4, Rt, va, ss, res);
	} else if ((fields == 4) ||
	    (fields == 5) ||
	    (fields == 6) ||
	    (fields == 7) ||
	    (fields == 12) ||
	    (fields == 13) ||
	    (fields == 0x14) ||
	    (fields == 0x15) ||
	    (fields == 0x1c) ||
	    (fields == 0x1d)) {
		CANNOTDECODE("simd", inst);
	} else if (fields == 8) {
		do_str(2, Rt, va, ss, res);
	} else if (fields == 9) {
		do_ldr(2, Rt, va, ss, res);
	} else if (fields == 10) {
		do_ldrs(2, 8, Rt, va, ss, res);
	} else if (fields == 11) {
		do_ldrs(2, 4, Rt, va, ss, res);
	} else if (fields == 0x10) {
		do_str(4, Rt, va, ss, res);
	} else if (fields == 0x11) {
		do_ldr(4, Rt, va, ss, res);
	} else if (fields == 0x12) {
		do_ldrs(4, 8, Rt, va, ss, res);
	} else if (fields == 0x18) {
		do_str(8, Rt, va, ss, res);
	} else if (fields == 0x19) {
		do_ldr(8, Rt, va, ss, res);
	} else if (fields == 0x1a) {
		do_prfm(Rt, va, res);
	} else {
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c3310++;

	return 0;
}

static int
run_c3311(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t size = BITS(inst, 31, 30),
	    V = BITS(inst, 26, 26),
	    opc = BITS(inst, 23, 22),
	    Rt = BITS(inst, 4, 0);
	uint8_t fields = (size << 3) | (V << 2) | opc;

	res->rr_num = 1;
	res->rr_addrdata[0].ad_addr = pa;

	if (fields == 0) {
		do_sttr(1, Rt, va, ss, res);
	} else if (fields == 1) {
		do_ldtr(1, Rt, va, ss, res);
	} else if (fields == 2) {
		do_ldtrs(1, 8, Rt, va, ss, res);
	} else if (fields == 3) {
		do_ldtrs(1, 4, Rt, va, ss, res);
	} else if (fields == 8) {
		do_sttr(2, Rt, va, ss, res);
	} else if (fields == 9) {
		do_ldtr(2, Rt, va, ss, res);
	} else if (fields == 10) {
		do_ldtrs(2, 8, Rt, va, ss, res);
	} else if (fields == 11) {
		do_ldtrs(2, 4, Rt, va, ss, res);
	} else if (fields == 0x10) {
		do_sttr(4, Rt, va, ss, res);
	} else if (fields == 0x11) {
		do_ldtr(4, Rt, va, ss, res);
	} else if (fields == 0x12) {
		do_ldtrs(4, 8, Rt, va, ss, res);
	} else if (fields == 0x18) {
		do_sttr(8, Rt, va, ss, res);
	} else if (fields == 0x19) {
		do_ldtr(8, Rt, va, ss, res);
	} else {
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c3311++;

	return 0;
}

static int
run_c3312(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t size = BITS(inst, 31, 30),
	    V = BITS(inst, 26, 26),
	    opc = BITS(inst, 23, 22),
	    Rt = BITS(inst, 4, 0);
	uint8_t fields = (size << 3) | (V << 2) | opc;

	res->rr_num = 1;
	res->rr_addrdata[0].ad_addr = pa;

	if (fields == 0) {
		do_str(1, Rt, va, ss, res);
	} else if (fields == 1) {
		do_ldr(1, Rt, va, ss, res);
	} else if (fields == 2) {
		do_ldrs(1, 8, Rt, va, ss, res);
	} else if (fields == 3) {
		do_ldrs(1, 4, Rt, va, ss, res);
	} else if ((fields == 4) ||
	    (fields == 5) ||
	    (fields == 6) ||
	    (fields == 7) ||
	    (fields == 12) ||
	    (fields == 13) ||
	    (fields == 0x14) ||
	    (fields == 0x15) ||
	    (fields == 0x1c) ||
	    (fields == 0x1d)) {
		CANNOTDECODE("simd", inst);
	} else if (fields == 8) {
		do_str(2, Rt, va, ss, res);
	} else if (fields == 9) {
		do_ldr(2, Rt, va, ss, res);
	} else if (fields == 10) {
		do_ldrs(2, 8, Rt, va, ss, res);
	} else if (fields == 11) {
		do_ldrs(2, 4, Rt, va, ss, res);
	} else if (fields == 0x10) {
		do_str(4, Rt, va, ss, res);
	} else if (fields == 0x11) {
		do_ldr(4, Rt, va, ss, res);
	} else if (fields == 0x12) {
		do_ldrs(4, 8, Rt, va, ss, res);
	} else if (fields == 0x18) {
		do_str(8, Rt, va, ss, res);
	} else if (fields == 0x19) {
		do_ldr(8, Rt, va, ss, res);
	} else if (fields == 0x1a) {
		do_prfm(Rt, va, res);
	} else {
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c3312++;

	return 0;
}

static int
run_c3313(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t size = BITS(inst, 31, 30),
	    V = BITS(inst, 26, 26),
	    opc = BITS(inst, 23, 22),
	    Rt = BITS(inst, 4, 0);
	uint8_t fields = (size << 3) | (V << 2) | opc;

	res->rr_num = 1;
	res->rr_addrdata[0].ad_addr = pa;

	if (fields == 0) {
		do_str(1, Rt, va, ss, res);
	} else if (fields == 1) {
		do_ldr(1, Rt, va, ss, res);
	} else if (fields == 2) {
		do_ldrs(1, 8, Rt, va, ss, res);
	} else if (fields == 3) {
		do_ldrs(1, 4, Rt, va, ss, res);
	} else if ((fields == 4) ||
	    (fields == 5) ||
	    (fields == 6) ||
	    (fields == 7) ||
	    (fields == 12) ||
	    (fields == 13) ||
	    (fields == 0x14) ||
	    (fields == 0x15) ||
	    (fields == 0x1c) ||
	    (fields == 0x1d)) {
		CANNOTDECODE("simd", inst);
	} else if (fields == 8) {
		do_str(2, Rt, va, ss, res);
	} else if (fields == 9) {
		do_ldr(2, Rt, va, ss, res);
	} else if (fields == 10) {
		do_ldrs(2, 8, Rt, va, ss, res);
	} else if (fields == 11) {
		do_ldrs(2, 4, Rt, va, ss, res);
	} else if (fields == 0x10) {
		do_str(4, Rt, va, ss, res);
	} else if (fields == 0x11) {
		do_ldr(4, Rt, va, ss, res);
	} else if (fields == 0x12) {
		do_ldrs(4, 8, Rt, va, ss, res);
	} else if (fields == 0x18) {
		do_str(8, Rt, va, ss, res);
	} else if (fields == 0x19) {
		do_ldr(8, Rt, va, ss, res);
	} else if (fields == 0x1a) {
		do_prfm(Rt, va, res);
	} else {
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c3313++;

	return 0;
}

static int
run_c3314(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t opc = BITS(inst, 31, 30),
	    V = BITS(inst, 26, 26),
	    L = BITS(inst, 22, 22),
	    Rt = BITS(inst, 4, 0),
	    Rt2 = BITS(inst, 14, 10);
	uint8_t fields = (opc << 2) | (V << 1) | L;

	res->rr_num = 2;
	res->rr_addrdata[0].ad_addr = pa;

	if (fields == 0) {
		do_stp(4, Rt, Rt2, va, ss, res);
	} else if (fields == 1) {
		do_ldp(4, Rt, Rt2, va, ss, res);
	} else if ((fields == 2) ||
	    (fields == 3) ||
	    (fields == 6) ||
	    (fields == 7) ||
	    (fields == 10) ||
	    (fields == 11)) {
		CANNOTDECODE("simd", inst);
	} else if (fields == 5) {
		do_ldpsw(Rt, Rt2, va, ss, res);
	} else if (fields == 8) {
		do_stp(8, Rt, Rt2, va, ss, res);
	} else if (fields == 9) {
		do_ldp(8, Rt, Rt2, va, ss, res);
	} else {
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c3314++;

	return 0;
}

static int
run_c3315(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t opc = BITS(inst, 31, 30),
	    V = BITS(inst, 26, 26),
	    L = BITS(inst, 22, 22),
	    Rt = BITS(inst, 4, 0),
	    Rt2 = BITS(inst, 14, 10);
	uint8_t fields = (opc << 2) | (V << 1) | L;

	res->rr_num = 2;
	res->rr_addrdata[0].ad_addr = pa;

	if (fields == 0) {
		do_stp(4, Rt, Rt2, va, ss, res);
	} else if (fields == 1) {
		do_ldp(4, Rt, Rt2, va, ss, res);
	} else if ((fields == 2) ||
	    (fields == 3) ||
	    (fields == 6) ||
	    (fields == 7) ||
	    (fields == 10) ||
	    (fields == 11)) {
		CANNOTDECODE("simd", inst);
	} else if (fields == 5) {
		do_ldpsw(Rt, Rt2, va, ss, res);
	} else if (fields == 8) {
		do_stp(8, Rt, Rt2, va, ss, res);
	} else if (fields == 9) {
		do_ldp(8, Rt, Rt2, va, ss, res);
	} else {
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c3315++;

	return 0;
}

static int
run_c3316(uint32_t inst, vm_offset_t pa, vm_offset_t va, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint32_t opc = BITS(inst, 31, 30),
	    V = BITS(inst, 26, 26),
	    L = BITS(inst, 22, 22),
	    Rt = BITS(inst, 4, 0),
	    Rt2 = BITS(inst, 14, 10);
	uint8_t fields = (opc << 2) | (V << 1) | L;

	res->rr_num = 2;
	res->rr_addrdata[0].ad_addr = pa;

	if (fields == 0) {
		do_stp(4, Rt, Rt2, va, ss, res);
	} else if (fields == 1) {
		do_ldp(4, Rt, Rt2, va, ss, res);
	} else if ((fields == 2) ||
	    (fields == 3) ||
	    (fields == 6) ||
	    (fields == 7) ||
	    (fields == 10) ||
	    (fields == 11)) {
		CANNOTDECODE("simd", inst);
	} else if (fields == 5) {
		do_ldpsw(Rt, Rt2, va, ss, res);
	} else if (fields == 8) {
		do_stp(8, Rt, Rt2, va, ss, res);
	} else if (fields == 9) {
		do_ldp(8, Rt, Rt2, va, ss, res);
	} else {
		CANNOTDECODE("unknown", inst);
	}

	stats.stat_decoder.sd_c3316++;

	return 0;
}

static bool
get_info_simd(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
#pragma unused(inst, ss, info)
	CANNOTDECODE("simd", inst);
	return false;
}

// load register (literal)
static bool
get_info_c335(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t opc = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t imm19 = BITS(inst, 23, 5);
	uint32_t fields = (opc << 1) | V;
	uint8_t scale;

	if (__builtin_expect(fields > 6, false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	assert(fields <= 6);

	if (V == 1) {
		scale = 2 + opc;
	} else {
		switch (opc) {
		case 0 ... 1:
			scale = 2 + opc;
			break;
		case 2:
			scale = 2;
			break;
		default:
			CANNOTDECODE("invalid", inst);
			return false;
		}
	}

	info->bytes = 1 << scale;
	info->addr = ss->ss_64.pc + (SIGN_EXTEND_64(imm19, 19) << 2);

	return true;
}

// load/store exclusive
static bool
get_info_c336(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t size = BITS(inst, 31, 30);
	uint32_t o2 = BITS(inst, 23, 23);
	uint32_t L = BITS(inst, 22, 22);
	uint32_t o1 = BITS(inst, 21, 21);
	uint32_t o0 = BITS(inst, 15, 15);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (size << 4) | (o2 << 3) | (L << 2) | (o1 << 1) | o0;

	if (__builtin_expect((2 <= fields && fields <= 3) ||
	    (6 <= fields && fields <= 8) ||
	    (10 <= fields && fields <= 12) ||
	    (14 <= fields && fields <= 15) ||
	    (18 <= fields && fields <= 19) ||
	    (22 <= fields && fields <= 24) ||
	    (26 <= fields && fields <= 28) ||
	    (30 <= fields && fields <= 31) ||
	    (40 == fields) ||
	    (42 <= fields && fields <= 44) ||
	    (46 <= fields && fields <= 47) ||
	    (56 == fields) ||
	    (58 <= fields && fields <= 60) ||
	    (62 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	info->bytes = (1 << size) << o1;
	info->addr = ss->ss_64.x[Rn];

	return true;
}

// load/store no-allocate pair (offset)
bool
get_info_c337(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t opc = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t L = BITS(inst, 22, 22);
	uint32_t imm7 = BITS(inst, 21, 15);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (opc << 2) | (V << 1) | L;
	uint8_t scale;

	if (__builtin_expect((4 <= fields && fields <= 5) ||
	    (12 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	if (V == 1) {
		scale = opc + 2;
	} else {
		scale = BITS(opc, 1, 1) + 2;
	}

	// double since it's pair
	info->bytes = 2 * (1 << scale);
	info->addr = ss->ss_64.x[Rn] + (SIGN_EXTEND_64(imm7, 7) << scale);

	return true;
}

// load/store reigster (immediate post-indexed)
static bool
get_info_c338(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t size = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t opc = BITS(inst, 23, 22);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (size << 3) | (V << 2) | opc;
	uint8_t scale;

	if (__builtin_expect((14 <= fields && fields <= 15) ||
	    (19 == fields) ||
	    (22 <= fields && fields <= 23) ||
	    (26 <= fields && fields <= 27) ||
	    (30 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	if (V == 1) {
		scale = BITS(opc, 1, 1) << 2 | size;
	} else {
		scale = size;
	}

	info->bytes = 1 << scale;
	// post-indexed
	info->addr = ss->ss_64.x[Rn];

	return true;
}

// load/store register (immediate pre-indexed)
static bool
get_info_c339(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t size = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t opc = BITS(inst, 23, 22);
	uint32_t imm9 = BITS(inst, 20, 12);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (size << 3) | (V << 2) | opc;
	uint8_t scale;

	if (__builtin_expect((14 <= fields && fields <= 15) ||
	    (19 == fields) ||
	    (22 <= fields && fields <= 23) ||
	    (26 <= fields && fields <= 27) ||
	    (30 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	if (V == 1) {
		scale = BITS(opc, 1, 1) << 2 | size;
	} else {
		scale = size;
	}

	info->bytes = 1 << scale;
	info->addr = ss->ss_64.x[Rn] + SIGN_EXTEND_64(imm9, 9);

	return true;
}

// load/store register (register offset)
static bool
get_info_c3310(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t size = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t opc = BITS(inst, 23, 22);
	uint32_t Rm = BITS(inst, 20, 16);
	uint32_t option = BITS(inst, 15, 13);
	uint32_t S = BITS(inst, 12, 12);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (size << 3) | (V << 2) | opc;
	uint32_t scale;

	if (__builtin_expect((14 <= fields && fields <= 15) ||
	    (19 == fields) ||
	    (22 <= fields && fields <= 23) ||
	    (27 == fields) ||
	    (30 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	if (V == 1) {
		scale = BITS(opc, 1, 1) | size;
	} else {
		scale = size;
	}

	info->bytes = 1 << scale;

	uint64_t m = ss->ss_64.x[Rm];
	uint8_t shift = (S == 1 ? scale : 0);

	switch (option) {
	case 0 ... 3:
		info->addr = ss->ss_64.x[Rn] + (ZERO_EXTEND_64(m, 8 << option) << shift);
		break;
	case 4 ... 7:
		info->addr = ss->ss_64.x[Rn] + (SIGN_EXTEND_64(m, 8 << BITS(option, 1, 0)) << shift);
		break;
	default:
		CANNOTDECODE("invalid", inst);
		return false;
	}

	return true;
}

// load/store register (unprivileged)
static bool
get_info_c3311(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t size = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t opc = BITS(inst, 23, 22);
	uint32_t imm9 = BITS(inst, 20, 12);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (size << 3) | (V << 2) | opc;

	if (__builtin_expect((4 <= fields && fields <= 7) ||
	    (12 <= fields && fields <= 15) ||
	    (19 <= fields && fields <= 23) ||
	    (26 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	info->bytes = 1 << size;
	info->addr = ss->ss_64.x[Rn] + SIGN_EXTEND_64(imm9, 9);

	return true;
}

// load/store register (unscaled immediate)
static bool
get_info_c3312(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t size = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t opc = BITS(inst, 23, 22);
	uint32_t imm9 = BITS(inst, 20, 12);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (size << 3) | (V << 2) | opc;
	uint32_t scale;

	if (__builtin_expect((14 <= fields && fields <= 15) ||
	    (19 == fields) ||
	    (22 <= fields && fields <= 23) ||
	    (27 == fields) ||
	    (30 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	if (V == 1) {
		scale = BITS(opc, 1, 1) << 2 | size;
	} else {
		scale = size;
	}

	info->bytes = 1 < scale;
	info->addr = ss->ss_64.x[Rn] + SIGN_EXTEND_64(imm9, 9);

	return true;
}

// load/store register (unsigned immediate)
bool
get_info_c3313(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t size = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t opc = BITS(inst, 23, 22);
	uint32_t imm12 = BITS(inst, 21, 10);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (size << 3) | (V << 2) | opc;
	uint32_t scale;

	if (__builtin_expect((14 <= fields && fields <= 15) ||
	    (19 == fields) ||
	    (22 <= fields && fields <= 23) ||
	    (27 == fields) ||
	    (30 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	if (V == 1) {
		scale = BITS(opc, 1, 1) << 2 | size;
	} else {
		scale = size;
	}

	info->bytes = 1 << scale;
	info->addr = ss->ss_64.x[Rn] + (ZERO_EXTEND_64(imm12, 12) << scale);

	return true;
}

// load/store register pair (offset)
static bool
get_info_c3314(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t opc = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t L = BITS(inst, 22, 22);
	uint32_t imm7 = BITS(inst, 21, 15);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (opc << 2) | (V << 1) | L;
	uint8_t scale = 2 + (opc >> 1);

	if (__builtin_expect((4 == fields) ||
	    (12 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	if (V == 1) {
		scale = 2 + opc;
	} else {
		scale = 2 + BITS(opc, 1, 1);
	}

	info->bytes = 2 * (1 << scale);
	info->addr = ss->ss_64.x[Rn] + (SIGN_EXTEND_64(imm7, 7) << scale);

	return true;
}

// load/store register pair (post-indexed)
static bool
get_info_c3315(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t opc = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t L = BITS(inst, 22, 22);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (opc << 2) | (V << 1) | L;
	uint8_t scale = 2 + (opc >> 1);

	if (__builtin_expect((4 == fields) ||
	    (12 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	if (V == 1) {
		scale = 2 + opc;
	} else {
		scale = 2 + BITS(opc, 1, 1);
	}

	info->bytes = 2 * (1 << scale);
	// post-indexed
	info->addr = ss->ss_64.x[Rn];

	return true;
}

// load/store register pair (pre-indexed)
static bool
get_info_c3316(uint32_t inst, arm_saved_state_t *ss, instruction_info_t *info)
{
	uint32_t opc = BITS(inst, 31, 30);
	uint32_t V = BITS(inst, 26, 26);
	uint32_t L = BITS(inst, 22, 22);
	uint32_t imm7 = BITS(inst, 21, 15);
	uint32_t Rn = BITS(inst, 9, 5);
	uint32_t fields = (opc << 2) | (V << 1) | L;
	uint8_t scale = 2 + (opc >> 1);

	if (__builtin_expect((4 == fields) ||
	    (12 <= fields), false)) {
		CANNOTDECODE("invalid", inst);
		return false;
	}

	if (V == 1) {
		scale = 2 + opc;
	} else {
		scale = 2 + BITS(opc, 1, 1);
	}

	info->bytes = 2 * (1 << scale);
	info->addr = ss->ss_64.x[Rn] + (SIGN_EXTEND_64(imm7, 7) << scale);

	return true;
}


//-------------------------------------------------------------------
// Globals
//
int
pgtrace_decode_and_run(uint32_t inst, vm_offset_t fva, vm_map_offset_t *cva_page, arm_saved_state_t *ss, pgtrace_run_result_t *res)
{
	uint8_t len = sizeof(typetbl) / sizeof(type_entry_t);
	run_t run = NULL;
	get_info_t get_info = NULL;
	vm_offset_t pa, cva;
	vm_offset_t cva_front_page = cva_page[0];
	vm_offset_t cva_cur_page = cva_page[1];
	instruction_info_t info;

	for (uint8_t i = 0; i < len; i++) {
		if ((typetbl[i].mask & inst) == typetbl[i].value) {
			run = typetbl[i].run;
			get_info = typetbl[i].get_info;
			break;
		}
	}

	assert(run != NULL && get_info != NULL);

	get_info(inst, ss, &info);

	if (info.addr == fva) {
		cva = cva_cur_page + (fva & ARM_PGMASK);
	} else {
		// which means a front page is not a tracing page
		cva = cva_front_page + (fva & ARM_PGMASK);
	}

	pa = mmu_kvtop(cva);
	if (!pa) {
		panic("%s: invalid address cva=%lx fva=%lx info.addr=%lx inst=%x", __func__, cva, fva, info.addr, inst);
	}

	absolutetime_to_nanoseconds(mach_absolute_time(), &res->rr_time);
	run(inst, pa, cva, ss, res);

	return 0;
}

void
pgtrace_decoder_get_stats(pgtrace_stats_t *s)
{
	memcpy((void *)&(s->stat_decoder), &(stats.stat_decoder), sizeof(stats.stat_decoder));
}
#endif
