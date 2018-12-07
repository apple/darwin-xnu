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
 * Created 2018 Derek Kumar
 */
#include <i386/asm.h>

.macro VPX
	vpxord $0, $0, $0
.endmacro

.macro PX
	pxor $0, $0
.endmacro

Entry(vzeroall)
	vzeroall
	ret

Entry(avx512_zero)
	vzeroall

	VPX %zmm16
	VPX %zmm17
	VPX %zmm18
	VPX %zmm19

	VPX %zmm20
	VPX %zmm21
	VPX %zmm22
	VPX %zmm23

	VPX %zmm24
	VPX %zmm25
	VPX %zmm26
	VPX %zmm27

	VPX %zmm28
	VPX %zmm29
	VPX %zmm30
	VPX %zmm31

	xor %eax, %eax
	kmovw %eax, %k1
	ret

Entry(xmmzeroall)
	PX %xmm0
	PX %xmm1
	PX %xmm2
	PX %xmm3

	PX %xmm4
	PX %xmm5
	PX %xmm6
	PX %xmm7

	PX %xmm8
	PX %xmm9
	PX %xmm10
	PX %xmm11

	PX %xmm12
	PX %xmm13
	PX %xmm14
	PX %xmm15

	ret
