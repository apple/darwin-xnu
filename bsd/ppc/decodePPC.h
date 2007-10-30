/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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

struct dcdtab {

	uint8_t		dcdFlgs;			/* Flags needed to decode */
#define dcdStep 0x80				/* Step to next table entry on non-match */
#define dcdJump 0x40				/* Jump to new entry in table. Index is in dcdMatch. */
#define dcdMask 0x0F				/* Index into mask table.  0 matches everything */

	uint8_t		dcdType;			/* Instruction type */
#define diINV  0x00
#define diTRP  0x01
#define diSC   0x02
#define diRFI  0x03
#define diB	   0x04
#define diBC   0x05
#define diBLR  0x06
#define diBCTR 0x07
#define diOR   0x08
#define diSPR  0x09
#define diCMN  0x0A
#define diPRV  0x0B

	uint16_t	dcdMatch;			/* Extended op code to match */
};

typedef struct dcdtab dcdtab;

static uint16_t masktab[] = {0x0000, 0x0003, 0x001C, 0x001E, 0x003E, /* Table of extended op masks */
	0x003F, 0x03FE, 0x03FF, 0x07FC, 0x07FE, 0x07FF};

static dcdtab insts[] = {
    { 0x40,      0,     64 },         //    0 Maj op =  0, jump to entry 64
    { 0x00,  diINV, 0x0000 },         //    1 Maj op =  1, invalid
    { 0x00,  diTRP, 0x0000 },         //    2 Maj op =  2, tdi
    { 0x00,  diTRP, 0x0000 },         //    3 Maj op =  3, twi
    { 0x40,      0,     65 },         //    4 Maj op =  4, jump to entry 65
    { 0x00,  diINV, 0x0000 },         //    5 Maj op =  5, invalid
    { 0x00,  diINV, 0x0000 },         //    6 Maj op =  6, invalid
    { 0x00,  diCMN, 0x0000 },         //    7 Maj op =  7, mulli
    { 0x00,  diCMN, 0x0000 },         //    8 Maj op =  8, subfic
    { 0x00,  diINV, 0x0000 },         //    9 Maj op =  9, invalid
    { 0x00,  diCMN, 0x0000 },         //   10 Maj op = 10, cmpli
    { 0x00,  diCMN, 0x0000 },         //   11 Maj op = 11, cmpi
    { 0x00,  diCMN, 0x0000 },         //   12 Maj op = 12, addic
    { 0x00,  diCMN, 0x0000 },         //   13 Maj op = 13, addic.
    { 0x00,  diCMN, 0x0000 },         //   14 Maj op = 14, addi
    { 0x00,  diCMN, 0x0000 },         //   15 Maj op = 15, addis
    { 0x00,   diBC, 0x0000 },         //   16 Maj op = 16, bc
    { 0x00,   diSC, 0x0000 },         //   17 Maj op = 17, sc
    { 0x00,    diB, 0x0000 },         //   18 Maj op = 18, b
    { 0x40,      0,    209 },         //   19 Maj op = 19, jump to entry 209
    { 0x00,  diCMN, 0x0000 },         //   20 Maj op = 20, rlwimi
    { 0x00,  diCMN, 0x0000 },         //   21 Maj op = 21, rlwinm
    { 0x00,  diINV, 0x0000 },         //   22 Maj op = 22, invalid
    { 0x00,  diCMN, 0x0000 },         //   23 Maj op = 23, rlwnm
    { 0x00,   diOR, 0x0000 },         //   24 Maj op = 24, ori
    { 0x00,  diCMN, 0x0000 },         //   25 Maj op = 25, oris
    { 0x00,  diCMN, 0x0000 },         //   26 Maj op = 26, xori
    { 0x00,  diCMN, 0x0000 },         //   27 Maj op = 27, xoris
    { 0x00,  diCMN, 0x0000 },         //   28 Maj op = 28, andi.
    { 0x00,  diCMN, 0x0000 },         //   29 Maj op = 29, andis.
    { 0x40,      0,    224 },         //   30 Maj op = 30, jump to entry 224
    { 0x40,      0,    230 },         //   31 Maj op = 31, jump to entry 230
    { 0x00,  diCMN, 0x0000 },         //   32 Maj op = 32, lwz
    { 0x00,  diCMN, 0x0000 },         //   33 Maj op = 33, lwzu
    { 0x00,  diCMN, 0x0000 },         //   34 Maj op = 34, lbz
    { 0x00,  diCMN, 0x0000 },         //   35 Maj op = 35, lbzu
    { 0x00,  diCMN, 0x0000 },         //   36 Maj op = 36, stw
    { 0x00,  diCMN, 0x0000 },         //   37 Maj op = 37, stwu
    { 0x00,  diCMN, 0x0000 },         //   38 Maj op = 38, stb
    { 0x00,  diCMN, 0x0000 },         //   39 Maj op = 39, stbu
    { 0x00,  diCMN, 0x0000 },         //   40 Maj op = 40, lhz
    { 0x00,  diCMN, 0x0000 },         //   41 Maj op = 41, lhzu
    { 0x00,  diCMN, 0x0000 },         //   42 Maj op = 42, lha
    { 0x00,  diCMN, 0x0000 },         //   43 Maj op = 43, lhau
    { 0x00,  diCMN, 0x0000 },         //   44 Maj op = 44, sth
    { 0x00,  diCMN, 0x0000 },         //   45 Maj op = 45, sthu
    { 0x00,  diCMN, 0x0000 },         //   46 Maj op = 46, lmw
    { 0x00,  diCMN, 0x0000 },         //   47 Maj op = 47, stmw
    { 0x00,  diCMN, 0x0000 },         //   48 Maj op = 48, lfs
    { 0x00,  diCMN, 0x0000 },         //   49 Maj op = 49, lfsu
    { 0x00,  diCMN, 0x0000 },         //   50 Maj op = 50, lfd
    { 0x00,  diCMN, 0x0000 },         //   51 Maj op = 51, lfdu
    { 0x00,  diCMN, 0x0000 },         //   52 Maj op = 52, stfs
    { 0x00,  diCMN, 0x0000 },         //   53 Maj op = 53, stfsu
    { 0x00,  diCMN, 0x0000 },         //   54 Maj op = 54, stfd
    { 0x00,  diCMN, 0x0000 },         //   55 Maj op = 55, stfdu
    { 0x00,  diINV, 0x0000 },         //   56 Maj op = 56, invalid
    { 0x00,  diINV, 0x0000 },         //   57 Maj op = 57, invalid
    { 0x40,      0,    365 },         //   58 Maj op = 58, jump to entry 365
    { 0x40,      0,    368 },         //   59 Maj op = 59, jump to entry 368
    { 0x00,  diINV, 0x0000 },         //   60 Maj op = 60, invalid
    { 0x00,  diINV, 0x0000 },         //   61 Maj op = 61, invalid
    { 0x40,      0,    378 },         //   62 Maj op = 62, jump to entry 378
    { 0x40,      0,    380 },         //   63 Maj op = 63, jump to entry 380
    { 0x09,  diCMN, 0x0200 },         //   64 Maj op =  0, mask = 07FE, xop = 0x0200 ( 256) - attn
    { 0x85,  diCMN, 0x0020 },         //   65 Maj op =  4, mask = 003F, xop = 0x0020 (  32) - vmhaddshs
    { 0x85,  diCMN, 0x0021 },         //   66 Maj op =  4, mask = 003F, xop = 0x0021 (  33) - vmhraddshs
    { 0x85,  diCMN, 0x0022 },         //   67 Maj op =  4, mask = 003F, xop = 0x0022 (  34) - vmladduhm
    { 0x85,  diCMN, 0x0024 },         //   68 Maj op =  4, mask = 003F, xop = 0x0024 (  36) - vmsumubm
    { 0x85,  diCMN, 0x0025 },         //   69 Maj op =  4, mask = 003F, xop = 0x0025 (  37) - vmsummbm
    { 0x85,  diCMN, 0x0026 },         //   70 Maj op =  4, mask = 003F, xop = 0x0026 (  38) - vmsumuhm
    { 0x85,  diCMN, 0x0027 },         //   71 Maj op =  4, mask = 003F, xop = 0x0027 (  39) - vmsumuhs
    { 0x85,  diCMN, 0x0028 },         //   72 Maj op =  4, mask = 003F, xop = 0x0028 (  40) - vmsumshm
    { 0x85,  diCMN, 0x0029 },         //   73 Maj op =  4, mask = 003F, xop = 0x0029 (  41) - vmsumshs
    { 0x85,  diCMN, 0x002A },         //   74 Maj op =  4, mask = 003F, xop = 0x002A (  42) - vsel
    { 0x85,  diCMN, 0x002B },         //   75 Maj op =  4, mask = 003F, xop = 0x002B (  43) - vperm
    { 0x85,  diCMN, 0x002C },         //   76 Maj op =  4, mask = 003F, xop = 0x002C (  44) - vsldoi
    { 0x85,  diCMN, 0x002E },         //   77 Maj op =  4, mask = 003F, xop = 0x002E (  46) - vmaddfp
    { 0x85,  diCMN, 0x002F },         //   78 Maj op =  4, mask = 003F, xop = 0x002F (  47) - vnmsubfp
    { 0x87,  diCMN, 0x0006 },         //   79 Maj op =  4, mask = 03FF, xop = 0x0006 (   6) - vcmpequb
    { 0x87,  diCMN, 0x0046 },         //   80 Maj op =  4, mask = 03FF, xop = 0x0046 (  70) - vcmpequh
    { 0x87,  diCMN, 0x0086 },         //   81 Maj op =  4, mask = 03FF, xop = 0x0086 ( 134) - vcmpequw
    { 0x87,  diCMN, 0x00C6 },         //   82 Maj op =  4, mask = 03FF, xop = 0x00C6 ( 198) - vcmpeqfp
    { 0x87,  diCMN, 0x01C6 },         //   83 Maj op =  4, mask = 03FF, xop = 0x01C6 ( 454) - vcmpgefp
    { 0x87,  diCMN, 0x0206 },         //   84 Maj op =  4, mask = 03FF, xop = 0x0206 ( 518) - vcmpgtub
    { 0x87,  diCMN, 0x0246 },         //   85 Maj op =  4, mask = 03FF, xop = 0x0246 ( 582) - vcmpgtuh
    { 0x87,  diCMN, 0x0286 },         //   86 Maj op =  4, mask = 03FF, xop = 0x0286 ( 646) - vcmpgtuw
    { 0x87,  diCMN, 0x02C6 },         //   87 Maj op =  4, mask = 03FF, xop = 0x02C6 ( 710) - vcmpgtfp
    { 0x87,  diCMN, 0x0306 },         //   88 Maj op =  4, mask = 03FF, xop = 0x0306 ( 774) - vcmpgtsb
    { 0x87,  diCMN, 0x0346 },         //   89 Maj op =  4, mask = 03FF, xop = 0x0346 ( 838) - vcmpgtsh
    { 0x87,  diCMN, 0x0386 },         //   90 Maj op =  4, mask = 03FF, xop = 0x0386 ( 902) - vcmpgtsw
    { 0x87,  diCMN, 0x03C6 },         //   91 Maj op =  4, mask = 03FF, xop = 0x03C6 ( 966) - vcmpbfp
    { 0x8A,  diCMN, 0x0000 },         //   92 Maj op =  4, mask = 07FF, xop = 0x0000 (   0) - vaddubm
    { 0x8A,  diCMN, 0x0002 },         //   93 Maj op =  4, mask = 07FF, xop = 0x0002 (   2) - vmaxub
    { 0x8A,  diCMN, 0x0004 },         //   94 Maj op =  4, mask = 07FF, xop = 0x0004 (   4) - vrlb
    { 0x8A,  diCMN, 0x0008 },         //   95 Maj op =  4, mask = 07FF, xop = 0x0008 (   8) - vmuloub
    { 0x8A,  diCMN, 0x000A },         //   96 Maj op =  4, mask = 07FF, xop = 0x000A (  10) - vaddfp
    { 0x8A,  diCMN, 0x000C },         //   97 Maj op =  4, mask = 07FF, xop = 0x000C (  12) - vmrghb
    { 0x8A,  diCMN, 0x000E },         //   98 Maj op =  4, mask = 07FF, xop = 0x000E (  14) - vpkuhum
    { 0x8A,  diCMN, 0x0040 },         //   99 Maj op =  4, mask = 07FF, xop = 0x0040 (  64) - vadduhm
    { 0x8A,  diCMN, 0x0042 },         //  100 Maj op =  4, mask = 07FF, xop = 0x0042 (  66) - vmaxuh
    { 0x8A,  diCMN, 0x0044 },         //  101 Maj op =  4, mask = 07FF, xop = 0x0044 (  68) - vrlh
    { 0x8A,  diCMN, 0x0048 },         //  102 Maj op =  4, mask = 07FF, xop = 0x0048 (  72) - vmulouh
    { 0x8A,  diCMN, 0x004A },         //  103 Maj op =  4, mask = 07FF, xop = 0x004A (  74) - vsubfp
    { 0x8A,  diCMN, 0x004C },         //  104 Maj op =  4, mask = 07FF, xop = 0x004C (  76) - vmrghh
    { 0x8A,  diCMN, 0x004E },         //  105 Maj op =  4, mask = 07FF, xop = 0x004E (  78) - vpkuwum
    { 0x8A,  diCMN, 0x0080 },         //  106 Maj op =  4, mask = 07FF, xop = 0x0080 ( 128) - vadduwm
    { 0x8A,  diCMN, 0x0082 },         //  107 Maj op =  4, mask = 07FF, xop = 0x0082 ( 130) - vmaxuw
    { 0x8A,  diCMN, 0x0084 },         //  108 Maj op =  4, mask = 07FF, xop = 0x0084 ( 132) - vrlw
    { 0x8A,  diCMN, 0x008C },         //  109 Maj op =  4, mask = 07FF, xop = 0x008C ( 140) - vmrghw
    { 0x8A,  diCMN, 0x008E },         //  110 Maj op =  4, mask = 07FF, xop = 0x008E ( 142) - vpkuhus
    { 0x8A,  diCMN, 0x00CE },         //  111 Maj op =  4, mask = 07FF, xop = 0x00CE ( 206) - vpkuwus
    { 0x8A,  diCMN, 0x0102 },         //  112 Maj op =  4, mask = 07FF, xop = 0x0102 ( 258) - vmaxsb
    { 0x8A,  diCMN, 0x0104 },         //  113 Maj op =  4, mask = 07FF, xop = 0x0104 ( 260) - vslb
    { 0x8A,  diCMN, 0x0108 },         //  114 Maj op =  4, mask = 07FF, xop = 0x0108 ( 264) - vmulosb
    { 0x8A,  diCMN, 0x010A },         //  115 Maj op =  4, mask = 07FF, xop = 0x010A ( 266) - vrefp
    { 0x8A,  diCMN, 0x010C },         //  116 Maj op =  4, mask = 07FF, xop = 0x010C ( 268) - vmrglb
    { 0x8A,  diCMN, 0x010E },         //  117 Maj op =  4, mask = 07FF, xop = 0x010E ( 270) - vpkshus
    { 0x8A,  diCMN, 0x0142 },         //  118 Maj op =  4, mask = 07FF, xop = 0x0142 ( 322) - vmaxsh
    { 0x8A,  diCMN, 0x0144 },         //  119 Maj op =  4, mask = 07FF, xop = 0x0144 ( 324) - vslh
    { 0x8A,  diCMN, 0x0148 },         //  120 Maj op =  4, mask = 07FF, xop = 0x0148 ( 328) - vmulosh
    { 0x8A,  diCMN, 0x014A },         //  121 Maj op =  4, mask = 07FF, xop = 0x014A ( 330) - vrsqrtefp
    { 0x8A,  diCMN, 0x014C },         //  122 Maj op =  4, mask = 07FF, xop = 0x014C ( 332) - vmrglh
    { 0x8A,  diCMN, 0x014E },         //  123 Maj op =  4, mask = 07FF, xop = 0x014E ( 334) - vpkswus
    { 0x8A,  diCMN, 0x0180 },         //  124 Maj op =  4, mask = 07FF, xop = 0x0180 ( 384) - vaddcuw
    { 0x8A,  diCMN, 0x0182 },         //  125 Maj op =  4, mask = 07FF, xop = 0x0182 ( 386) - vmaxsw
    { 0x8A,  diCMN, 0x0184 },         //  126 Maj op =  4, mask = 07FF, xop = 0x0184 ( 388) - vslw
    { 0x8A,  diCMN, 0x018A },         //  127 Maj op =  4, mask = 07FF, xop = 0x018A ( 394) - vexptefp
    { 0x8A,  diCMN, 0x018C },         //  128 Maj op =  4, mask = 07FF, xop = 0x018C ( 396) - vmrglw
    { 0x8A,  diCMN, 0x018E },         //  129 Maj op =  4, mask = 07FF, xop = 0x018E ( 398) - vpkshss
    { 0x8A,  diCMN, 0x01C4 },         //  130 Maj op =  4, mask = 07FF, xop = 0x01C4 ( 452) - vsl
    { 0x8A,  diCMN, 0x01CA },         //  131 Maj op =  4, mask = 07FF, xop = 0x01CA ( 458) - vlogefp
    { 0x8A,  diCMN, 0x01CE },         //  132 Maj op =  4, mask = 07FF, xop = 0x01CE ( 462) - vpkswss
    { 0x8A,  diCMN, 0x0200 },         //  133 Maj op =  4, mask = 07FF, xop = 0x0200 ( 512) - vaddubs
    { 0x8A,  diCMN, 0x0202 },         //  134 Maj op =  4, mask = 07FF, xop = 0x0202 ( 514) - vminub
    { 0x8A,  diCMN, 0x0204 },         //  135 Maj op =  4, mask = 07FF, xop = 0x0204 ( 516) - vsrb
    { 0x8A,  diCMN, 0x0208 },         //  136 Maj op =  4, mask = 07FF, xop = 0x0208 ( 520) - vmuleub
    { 0x8A,  diCMN, 0x020A },         //  137 Maj op =  4, mask = 07FF, xop = 0x020A ( 522) - vrfin
    { 0x8A,  diCMN, 0x020C },         //  138 Maj op =  4, mask = 07FF, xop = 0x020C ( 524) - vspltb
    { 0x8A,  diCMN, 0x020E },         //  139 Maj op =  4, mask = 07FF, xop = 0x020E ( 526) - vupkhsb
    { 0x8A,  diCMN, 0x0240 },         //  140 Maj op =  4, mask = 07FF, xop = 0x0240 ( 576) - vadduhs
    { 0x8A,  diCMN, 0x0242 },         //  141 Maj op =  4, mask = 07FF, xop = 0x0242 ( 578) - vminuh
    { 0x8A,  diCMN, 0x0244 },         //  142 Maj op =  4, mask = 07FF, xop = 0x0244 ( 580) - vsrh
    { 0x8A,  diCMN, 0x0248 },         //  143 Maj op =  4, mask = 07FF, xop = 0x0248 ( 584) - vmuleuh
    { 0x8A,  diCMN, 0x024A },         //  144 Maj op =  4, mask = 07FF, xop = 0x024A ( 586) - vrfiz
    { 0x8A,  diCMN, 0x024C },         //  145 Maj op =  4, mask = 07FF, xop = 0x024C ( 588) - vsplth
    { 0x8A,  diCMN, 0x024E },         //  146 Maj op =  4, mask = 07FF, xop = 0x024E ( 590) - vupkhsh
    { 0x8A,  diCMN, 0x0280 },         //  147 Maj op =  4, mask = 07FF, xop = 0x0280 ( 640) - vadduws
    { 0x8A,  diCMN, 0x0282 },         //  148 Maj op =  4, mask = 07FF, xop = 0x0282 ( 642) - vminuw
    { 0x8A,  diCMN, 0x0284 },         //  149 Maj op =  4, mask = 07FF, xop = 0x0284 ( 644) - vsrw
    { 0x8A,  diCMN, 0x028A },         //  150 Maj op =  4, mask = 07FF, xop = 0x028A ( 650) - vrfip
    { 0x8A,  diCMN, 0x028C },         //  151 Maj op =  4, mask = 07FF, xop = 0x028C ( 652) - vspltw
    { 0x8A,  diCMN, 0x028E },         //  152 Maj op =  4, mask = 07FF, xop = 0x028E ( 654) - vupklsb
    { 0x8A,  diCMN, 0x02C4 },         //  153 Maj op =  4, mask = 07FF, xop = 0x02C4 ( 708) - vsr
    { 0x8A,  diCMN, 0x02CA },         //  154 Maj op =  4, mask = 07FF, xop = 0x02CA ( 714) - vrfim
    { 0x8A,  diCMN, 0x02CE },         //  155 Maj op =  4, mask = 07FF, xop = 0x02CE ( 718) - vupklsh
    { 0x8A,  diCMN, 0x0300 },         //  156 Maj op =  4, mask = 07FF, xop = 0x0300 ( 768) - vaddsbs
    { 0x8A,  diCMN, 0x0302 },         //  157 Maj op =  4, mask = 07FF, xop = 0x0302 ( 770) - vminsb
    { 0x8A,  diCMN, 0x0304 },         //  158 Maj op =  4, mask = 07FF, xop = 0x0304 ( 772) - vsrab
    { 0x8A,  diCMN, 0x0308 },         //  159 Maj op =  4, mask = 07FF, xop = 0x0308 ( 776) - vmulesb
    { 0x8A,  diCMN, 0x030A },         //  160 Maj op =  4, mask = 07FF, xop = 0x030A ( 778) - vcfux
    { 0x8A,  diCMN, 0x030C },         //  161 Maj op =  4, mask = 07FF, xop = 0x030C ( 780) - vspltisb
    { 0x8A,  diCMN, 0x030E },         //  162 Maj op =  4, mask = 07FF, xop = 0x030E ( 782) - vpkpx
    { 0x8A,  diCMN, 0x0340 },         //  163 Maj op =  4, mask = 07FF, xop = 0x0340 ( 832) - vaddshs
    { 0x8A,  diCMN, 0x0342 },         //  164 Maj op =  4, mask = 07FF, xop = 0x0342 ( 834) - vminsh
    { 0x8A,  diCMN, 0x0344 },         //  165 Maj op =  4, mask = 07FF, xop = 0x0344 ( 836) - vsrah
    { 0x8A,  diCMN, 0x0348 },         //  166 Maj op =  4, mask = 07FF, xop = 0x0348 ( 840) - vmulesh
    { 0x8A,  diCMN, 0x034A },         //  167 Maj op =  4, mask = 07FF, xop = 0x034A ( 842) - vcfsx
    { 0x8A,  diCMN, 0x034C },         //  168 Maj op =  4, mask = 07FF, xop = 0x034C ( 844) - vspltish
    { 0x8A,  diCMN, 0x034E },         //  169 Maj op =  4, mask = 07FF, xop = 0x034E ( 846) - vupkhpx
    { 0x8A,  diCMN, 0x0380 },         //  170 Maj op =  4, mask = 07FF, xop = 0x0380 ( 896) - vaddsws
    { 0x8A,  diCMN, 0x0382 },         //  171 Maj op =  4, mask = 07FF, xop = 0x0382 ( 898) - vminsw
    { 0x8A,  diCMN, 0x0384 },         //  172 Maj op =  4, mask = 07FF, xop = 0x0384 ( 900) - vsraw
    { 0x8A,  diCMN, 0x038A },         //  173 Maj op =  4, mask = 07FF, xop = 0x038A ( 906) - vctuxs
    { 0x8A,  diCMN, 0x038C },         //  174 Maj op =  4, mask = 07FF, xop = 0x038C ( 908) - vspltisw
    { 0x8A,  diCMN, 0x03CA },         //  175 Maj op =  4, mask = 07FF, xop = 0x03CA ( 970) - vctsxs
    { 0x8A,  diCMN, 0x03CE },         //  176 Maj op =  4, mask = 07FF, xop = 0x03CE ( 974) - vupklpx
    { 0x8A,  diCMN, 0x0400 },         //  177 Maj op =  4, mask = 07FF, xop = 0x0400 (1024) - vsububm
    { 0x8A,  diCMN, 0x0402 },         //  178 Maj op =  4, mask = 07FF, xop = 0x0402 (1026) - vavgub
    { 0x8A,  diCMN, 0x0404 },         //  179 Maj op =  4, mask = 07FF, xop = 0x0404 (1028) - vand
    { 0x8A,  diCMN, 0x040A },         //  180 Maj op =  4, mask = 07FF, xop = 0x040A (1034) - vmaxfp
    { 0x8A,  diCMN, 0x040C },         //  181 Maj op =  4, mask = 07FF, xop = 0x040C (1036) - vslo
    { 0x8A,  diCMN, 0x0440 },         //  182 Maj op =  4, mask = 07FF, xop = 0x0440 (1088) - vsubuhm
    { 0x8A,  diCMN, 0x0442 },         //  183 Maj op =  4, mask = 07FF, xop = 0x0442 (1090) - vavguh
    { 0x8A,  diCMN, 0x0444 },         //  184 Maj op =  4, mask = 07FF, xop = 0x0444 (1092) - vandc
    { 0x8A,  diCMN, 0x044A },         //  185 Maj op =  4, mask = 07FF, xop = 0x044A (1098) - vminfp
    { 0x8A,  diCMN, 0x044C },         //  186 Maj op =  4, mask = 07FF, xop = 0x044C (1100) - vsro
    { 0x8A,  diCMN, 0x0480 },         //  187 Maj op =  4, mask = 07FF, xop = 0x0480 (1152) - vsubuwm
    { 0x8A,  diCMN, 0x0482 },         //  188 Maj op =  4, mask = 07FF, xop = 0x0482 (1154) - vavguw
    { 0x8A,  diCMN, 0x0484 },         //  189 Maj op =  4, mask = 07FF, xop = 0x0484 (1156) - vor
    { 0x8A,  diCMN, 0x04C4 },         //  190 Maj op =  4, mask = 07FF, xop = 0x04C4 (1220) - vxor
    { 0x8A,  diCMN, 0x0502 },         //  191 Maj op =  4, mask = 07FF, xop = 0x0502 (1282) - vavgsb
    { 0x8A,  diCMN, 0x0504 },         //  192 Maj op =  4, mask = 07FF, xop = 0x0504 (1284) - vnor
    { 0x8A,  diCMN, 0x0542 },         //  193 Maj op =  4, mask = 07FF, xop = 0x0542 (1346) - vavgsh
    { 0x8A,  diCMN, 0x0580 },         //  194 Maj op =  4, mask = 07FF, xop = 0x0580 (1408) - vsubcuw
    { 0x8A,  diCMN, 0x0582 },         //  195 Maj op =  4, mask = 07FF, xop = 0x0582 (1410) - vavgsw
    { 0x8A,  diCMN, 0x0600 },         //  196 Maj op =  4, mask = 07FF, xop = 0x0600 (1536) - vsububs
    { 0x8A,  diCMN, 0x0604 },         //  197 Maj op =  4, mask = 07FF, xop = 0x0604 (1540) - mfvscr
    { 0x8A,  diCMN, 0x0608 },         //  198 Maj op =  4, mask = 07FF, xop = 0x0608 (1544) - vsum4ubs
    { 0x8A,  diCMN, 0x0640 },         //  199 Maj op =  4, mask = 07FF, xop = 0x0640 (1600) - vsubuhs
    { 0x8A,  diCMN, 0x0644 },         //  200 Maj op =  4, mask = 07FF, xop = 0x0644 (1604) - mtvscr
    { 0x8A,  diCMN, 0x0648 },         //  201 Maj op =  4, mask = 07FF, xop = 0x0648 (1608) - vsum4shs
    { 0x8A,  diCMN, 0x0680 },         //  202 Maj op =  4, mask = 07FF, xop = 0x0680 (1664) - vsubuws
    { 0x8A,  diCMN, 0x0688 },         //  203 Maj op =  4, mask = 07FF, xop = 0x0688 (1672) - vsum2sws
    { 0x8A,  diCMN, 0x0700 },         //  204 Maj op =  4, mask = 07FF, xop = 0x0700 (1792) - vsubsbs
    { 0x8A,  diCMN, 0x0708 },         //  205 Maj op =  4, mask = 07FF, xop = 0x0708 (1800) - vsum4sbs
    { 0x8A,  diCMN, 0x0740 },         //  206 Maj op =  4, mask = 07FF, xop = 0x0740 (1856) - vsubshs
    { 0x8A,  diCMN, 0x0780 },         //  207 Maj op =  4, mask = 07FF, xop = 0x0780 (1920) - vsubsws
    { 0x0A,  diCMN, 0x0788 },         //  208 Maj op =  4, mask = 07FF, xop = 0x0788 (1928) - vsumsws
    { 0x89,  diCMN, 0x0000 },         //  209 Maj op = 19, mask = 07FE, xop = 0x0000 (   0) - mcrf
    { 0x89,  diBLR, 0x0020 },         //  210 Maj op = 19, mask = 07FE, xop = 0x0020 (  16) - bclr
    { 0x89,  diPRV, 0x0024 },         //  211 Maj op = 19, mask = 07FE, xop = 0x0024 (  18) - rfid
    { 0x89,  diCMN, 0x0042 },         //  212 Maj op = 19, mask = 07FE, xop = 0x0042 (  33) - crnor
    { 0x89,  diPRV, 0x0064 },         //  213 Maj op = 19, mask = 07FE, xop = 0x0064 (  50) - rfi
    { 0x89,  diCMN, 0x0102 },         //  214 Maj op = 19, mask = 07FE, xop = 0x0102 ( 129) - crandc
    { 0x89,  diCMN, 0x012C },         //  215 Maj op = 19, mask = 07FE, xop = 0x012C ( 150) - isync
    { 0x89,  diCMN, 0x0182 },         //  216 Maj op = 19, mask = 07FE, xop = 0x0182 ( 193) - crxor
    { 0x89,  diCMN, 0x01C2 },         //  217 Maj op = 19, mask = 07FE, xop = 0x01C2 ( 225) - crnand
    { 0x89,  diCMN, 0x0202 },         //  218 Maj op = 19, mask = 07FE, xop = 0x0202 ( 257) - crand
    { 0x89,  diPRV, 0x0224 },         //  219 Maj op = 19, mask = 07FE, xop = 0x0224 ( 274) - hrfid
    { 0x89,  diCMN, 0x0242 },         //  220 Maj op = 19, mask = 07FE, xop = 0x0242 ( 289) - creqv
    { 0x89,  diCMN, 0x0342 },         //  221 Maj op = 19, mask = 07FE, xop = 0x0342 ( 417) - crorc
    { 0x89,  diCMN, 0x0382 },         //  222 Maj op = 19, mask = 07FE, xop = 0x0382 ( 449) - cror
    { 0x09, diBCTR, 0x0420 },         //  223 Maj op = 19, mask = 07FE, xop = 0x0420 ( 528) - bctr
    { 0x82,  diCMN, 0x0000 },         //  224 Maj op = 30, mask = 001C, xop = 0x0000 (   0) - rldicl
    { 0x82,  diCMN, 0x0004 },         //  225 Maj op = 30, mask = 001C, xop = 0x0004 (   1) - rldicr
    { 0x82,  diCMN, 0x0008 },         //  226 Maj op = 30, mask = 001C, xop = 0x0008 (   2) - rldic
    { 0x82,  diCMN, 0x000C },         //  227 Maj op = 30, mask = 001C, xop = 0x000C (   3) - rldimi
    { 0x83,  diCMN, 0x0010 },         //  228 Maj op = 30, mask = 001E, xop = 0x0010 (   8) - rldcl
    { 0x03,  diCMN, 0x0012 },         //  229 Maj op = 30, mask = 001E, xop = 0x0012 (   9) - rldcr
    { 0x86,  diCMN, 0x0010 },         //  230 Maj op = 31, mask = 03FE, xop = 0x0010 (   8) - subfc
    { 0x86,  diCMN, 0x0012 },         //  231 Maj op = 31, mask = 03FE, xop = 0x0012 (   9) - mulhdu
    { 0x86,  diCMN, 0x0014 },         //  232 Maj op = 31, mask = 03FE, xop = 0x0014 (  10) - addc
    { 0x86,  diCMN, 0x0016 },         //  233 Maj op = 31, mask = 03FE, xop = 0x0016 (  11) - mulhwu
    { 0x86,  diCMN, 0x0050 },         //  234 Maj op = 31, mask = 03FE, xop = 0x0050 (  40) - subf
    { 0x86,  diCMN, 0x0092 },         //  235 Maj op = 31, mask = 03FE, xop = 0x0092 (  73) - mulhd
    { 0x86,  diCMN, 0x0096 },         //  236 Maj op = 31, mask = 03FE, xop = 0x0096 (  75) - mulhw
    { 0x86,  diCMN, 0x00D0 },         //  237 Maj op = 31, mask = 03FE, xop = 0x00D0 ( 104) - neg
    { 0x86,  diCMN, 0x0110 },         //  238 Maj op = 31, mask = 03FE, xop = 0x0110 ( 136) - subfe
    { 0x86,  diCMN, 0x0114 },         //  239 Maj op = 31, mask = 03FE, xop = 0x0114 ( 138) - adde
    { 0x86,  diCMN, 0x0190 },         //  240 Maj op = 31, mask = 03FE, xop = 0x0190 ( 200) - subfze
    { 0x86,  diCMN, 0x0194 },         //  241 Maj op = 31, mask = 03FE, xop = 0x0194 ( 202) - addze
    { 0x86,  diCMN, 0x01D0 },         //  242 Maj op = 31, mask = 03FE, xop = 0x01D0 ( 232) - subfme
    { 0x86,  diCMN, 0x01D2 },         //  243 Maj op = 31, mask = 03FE, xop = 0x01D2 ( 233) - mulld
    { 0x86,  diCMN, 0x01D4 },         //  244 Maj op = 31, mask = 03FE, xop = 0x01D4 ( 234) - addme
    { 0x86,  diCMN, 0x01D6 },         //  245 Maj op = 31, mask = 03FE, xop = 0x01D6 ( 235) - mullw
    { 0x86,  diCMN, 0x0214 },         //  246 Maj op = 31, mask = 03FE, xop = 0x0214 ( 266) - add
    { 0x86,  diCMN, 0x0392 },         //  247 Maj op = 31, mask = 03FE, xop = 0x0392 ( 457) - divdu
    { 0x86,  diCMN, 0x0396 },         //  248 Maj op = 31, mask = 03FE, xop = 0x0396 ( 459) - divwu
    { 0x86,  diCMN, 0x03D2 },         //  249 Maj op = 31, mask = 03FE, xop = 0x03D2 ( 489) - divd
    { 0x86,  diCMN, 0x03D6 },         //  250 Maj op = 31, mask = 03FE, xop = 0x03D6 ( 491) - divw
    { 0x88,  diCMN, 0x0674 },         //  251 Maj op = 31, mask = 07FC, xop = 0x0674 ( 413) - sradi
    { 0x89,  diCMN, 0x0000 },         //  252 Maj op = 31, mask = 07FE, xop = 0x0000 (   0) - cmp
    { 0x89,  diTRP, 0x0008 },         //  253 Maj op = 31, mask = 07FE, xop = 0x0008 (   4) - tw
    { 0x89,  diCMN, 0x000C },         //  254 Maj op = 31, mask = 07FE, xop = 0x000C (   6) - lvsl
    { 0x89,  diCMN, 0x000E },         //  255 Maj op = 31, mask = 07FE, xop = 0x000E (   7) - lvebx
    { 0x89,  diCMN, 0x0026 },         //  256 Maj op = 31, mask = 07FE, xop = 0x0026 (  19) - mfcr
    { 0x89,  diCMN, 0x0028 },         //  257 Maj op = 31, mask = 07FE, xop = 0x0028 (  20) - lwarx
    { 0x89,  diCMN, 0x002A },         //  258 Maj op = 31, mask = 07FE, xop = 0x002A (  21) - ldx
    { 0x89,  diCMN, 0x002E },         //  259 Maj op = 31, mask = 07FE, xop = 0x002E (  23) - lwzx
    { 0x89,  diCMN, 0x0030 },         //  260 Maj op = 31, mask = 07FE, xop = 0x0030 (  24) - slw
    { 0x89,  diCMN, 0x0034 },         //  261 Maj op = 31, mask = 07FE, xop = 0x0034 (  26) - cntlzw
    { 0x89,  diCMN, 0x0036 },         //  262 Maj op = 31, mask = 07FE, xop = 0x0036 (  27) - sld
    { 0x89,  diCMN, 0x0038 },         //  263 Maj op = 31, mask = 07FE, xop = 0x0038 (  28) - and
    { 0x89,  diCMN, 0x0040 },         //  264 Maj op = 31, mask = 07FE, xop = 0x0040 (  32) - cmpl
    { 0x89,  diCMN, 0x004C },         //  265 Maj op = 31, mask = 07FE, xop = 0x004C (  38) - lvsr
    { 0x89,  diCMN, 0x004E },         //  266 Maj op = 31, mask = 07FE, xop = 0x004E (  39) - lvehx
    { 0x89,  diCMN, 0x006A },         //  267 Maj op = 31, mask = 07FE, xop = 0x006A (  53) - ldux
    { 0x89,  diCMN, 0x006C },         //  268 Maj op = 31, mask = 07FE, xop = 0x006C (  54) - dcbst
    { 0x89,  diCMN, 0x006E },         //  269 Maj op = 31, mask = 07FE, xop = 0x006E (  55) - lwzux
    { 0x89,  diCMN, 0x0074 },         //  270 Maj op = 31, mask = 07FE, xop = 0x0074 (  58) - cntlzd
    { 0x89,  diCMN, 0x0078 },         //  271 Maj op = 31, mask = 07FE, xop = 0x0078 (  60) - andc
    { 0x89,  diTRP, 0x0088 },         //  272 Maj op = 31, mask = 07FE, xop = 0x0088 (  68) - td
    { 0x89,  diCMN, 0x008E },         //  273 Maj op = 31, mask = 07FE, xop = 0x008E (  71) - lvewx
    { 0x89,  diPRV, 0x00A6 },         //  274 Maj op = 31, mask = 07FE, xop = 0x00A6 (  83) - mfmsr
    { 0x89,  diCMN, 0x00A8 },         //  275 Maj op = 31, mask = 07FE, xop = 0x00A8 (  84) - ldarx
    { 0x89,  diCMN, 0x00AC },         //  276 Maj op = 31, mask = 07FE, xop = 0x00AC (  86) - dcbf
    { 0x89,  diCMN, 0x00AE },         //  277 Maj op = 31, mask = 07FE, xop = 0x00AE (  87) - lbzx
    { 0x89,  diCMN, 0x00CE },         //  278 Maj op = 31, mask = 07FE, xop = 0x00CE ( 103) - lvx
    { 0x89,  diCMN, 0x00EE },         //  279 Maj op = 31, mask = 07FE, xop = 0x00EE ( 119) - lbzux
    { 0x89,  diCMN, 0x00F8 },         //  280 Maj op = 31, mask = 07FE, xop = 0x00F8 ( 124) - nor
    { 0x89,  diCMN, 0x010E },         //  281 Maj op = 31, mask = 07FE, xop = 0x010E ( 135) - stvebx
    { 0x89,  diCMN, 0x0120 },         //  282 Maj op = 31, mask = 07FE, xop = 0x0120 ( 144) - mtcrf
    { 0x89,  diPRV, 0x0124 },         //  283 Maj op = 31, mask = 07FE, xop = 0x0124 ( 146) - mtmsr
    { 0x89,  diCMN, 0x012A },         //  284 Maj op = 31, mask = 07FE, xop = 0x012A ( 149) - stdx
    { 0x89,  diCMN, 0x012C },         //  285 Maj op = 31, mask = 07FE, xop = 0x012C ( 150) - stwcx
    { 0x89,  diCMN, 0x012E },         //  286 Maj op = 31, mask = 07FE, xop = 0x012E ( 151) - stwx
    { 0x89,  diCMN, 0x014E },         //  287 Maj op = 31, mask = 07FE, xop = 0x014E ( 167) - stvehx
    { 0x89,  diPRV, 0x0164 },         //  288 Maj op = 31, mask = 07FE, xop = 0x0164 ( 178) - mtmsrd
    { 0x89,  diCMN, 0x016A },         //  289 Maj op = 31, mask = 07FE, xop = 0x016A ( 181) - stdux
    { 0x89,  diCMN, 0x016E },         //  290 Maj op = 31, mask = 07FE, xop = 0x016E ( 183) - stwux
    { 0x89,  diCMN, 0x018E },         //  291 Maj op = 31, mask = 07FE, xop = 0x018E ( 199) - stvewx
    { 0x89,  diCMN, 0x01A4 },         //  292 Maj op = 31, mask = 07FE, xop = 0x01A4 ( 210) - mtsr
    { 0x89,  diCMN, 0x01AC },         //  293 Maj op = 31, mask = 07FE, xop = 0x01AC ( 214) - stdcx.
    { 0x89,  diCMN, 0x01AE },         //  294 Maj op = 31, mask = 07FE, xop = 0x01AE ( 215) - stbx
    { 0x89,  diCMN, 0x01CE },         //  295 Maj op = 31, mask = 07FE, xop = 0x01CE ( 231) - stvx
    { 0x89,  diPRV, 0x01E4 },         //  296 Maj op = 31, mask = 07FE, xop = 0x01E4 ( 242) - mtsrin
    { 0x89,  diCMN, 0x01EC },         //  297 Maj op = 31, mask = 07FE, xop = 0x01EC ( 246) - dcbtst
    { 0x89,  diCMN, 0x01EE },         //  298 Maj op = 31, mask = 07FE, xop = 0x01EE ( 247) - stbux
    { 0x89,  diPRV, 0x0224 },         //  299 Maj op = 31, mask = 07FE, xop = 0x0224 ( 274) - tlbiel
    { 0x89,  diCMN, 0x022C },         //  300 Maj op = 31, mask = 07FE, xop = 0x022C ( 278) - dcbt
    { 0x89,  diCMN, 0x022E },         //  301 Maj op = 31, mask = 07FE, xop = 0x022E ( 279) - lhzx
    { 0x89,  diCMN, 0x0238 },         //  302 Maj op = 31, mask = 07FE, xop = 0x0238 ( 284) - eqv
    { 0x89,  diPRV, 0x0264 },         //  303 Maj op = 31, mask = 07FE, xop = 0x0264 ( 306) - tlbie
    { 0x89,  diPRV, 0x026C },         //  304 Maj op = 31, mask = 07FE, xop = 0x026C ( 310) - eciwx
    { 0x89,  diCMN, 0x026E },         //  305 Maj op = 31, mask = 07FE, xop = 0x026E ( 311) - lhzux
    { 0x89,  diCMN, 0x0278 },         //  306 Maj op = 31, mask = 07FE, xop = 0x0278 ( 316) - xor
    { 0x89,  diSPR, 0x02A6 },         //  307 Maj op = 31, mask = 07FE, xop = 0x02A6 ( 339) - mfspr
    { 0x89,  diCMN, 0x02AA },         //  308 Maj op = 31, mask = 07FE, xop = 0x02AA ( 341) - lwax
    { 0x89,  diCMN, 0x02AC },         //  309 Maj op = 31, mask = 07FE, xop = 0x02AC ( 342) - dst
    { 0x89,  diCMN, 0x02AE },         //  310 Maj op = 31, mask = 07FE, xop = 0x02AE ( 343) - lhax
    { 0x89,  diCMN, 0x02CE },         //  311 Maj op = 31, mask = 07FE, xop = 0x02CE ( 359) - lvxl
    { 0x89,  diPRV, 0x02E4 },         //  312 Maj op = 31, mask = 07FE, xop = 0x02E4 ( 370) - tlbia
    { 0x89,  diCMN, 0x02E6 },         //  313 Maj op = 31, mask = 07FE, xop = 0x02E6 ( 371) - mftb
    { 0x89,  diCMN, 0x02EA },         //  314 Maj op = 31, mask = 07FE, xop = 0x02EA ( 373) - lwaux
    { 0x89,  diCMN, 0x02EC },         //  315 Maj op = 31, mask = 07FE, xop = 0x02EC ( 374) - dstst
    { 0x89,  diCMN, 0x02EE },         //  316 Maj op = 31, mask = 07FE, xop = 0x02EE ( 375) - lhaux
    { 0x89,  diPRV, 0x0324 },         //  317 Maj op = 31, mask = 07FE, xop = 0x0324 ( 402) - slbmte
    { 0x89,  diCMN, 0x032E },         //  318 Maj op = 31, mask = 07FE, xop = 0x032E ( 407) - sthx
    { 0x89,  diCMN, 0x0338 },         //  319 Maj op = 31, mask = 07FE, xop = 0x0338 ( 412) - orc
    { 0x89,  diPRV, 0x0364 },         //  320 Maj op = 31, mask = 07FE, xop = 0x0364 ( 434) - slbie
    { 0x89,  diPRV, 0x036C },         //  321 Maj op = 31, mask = 07FE, xop = 0x036C ( 438) - ecowx
    { 0x89,  diCMN, 0x036E },         //  322 Maj op = 31, mask = 07FE, xop = 0x036E ( 439) - sthux
    { 0x89,   diOR, 0x0378 },         //  323 Maj op = 31, mask = 07FE, xop = 0x0378 ( 444) - or
    { 0x89,  diSPR, 0x03A6 },         //  324 Maj op = 31, mask = 07FE, xop = 0x03A6 ( 467) - mtspr
    { 0x89,  diCMN, 0x03B8 },         //  325 Maj op = 31, mask = 07FE, xop = 0x03B8 ( 476) - nand
    { 0x89,  diCMN, 0x03CE },         //  326 Maj op = 31, mask = 07FE, xop = 0x03CE ( 487) - stvxl
    { 0x89,  diPRV, 0x03E4 },         //  327 Maj op = 31, mask = 07FE, xop = 0x03E4 ( 498) - slbia
    { 0x89,  diCMN, 0x0400 },         //  328 Maj op = 31, mask = 07FE, xop = 0x0400 ( 512) - mcrxr
    { 0x89,  diCMN, 0x042A },         //  329 Maj op = 31, mask = 07FE, xop = 0x042A ( 533) - lswx
    { 0x89,  diCMN, 0x042C },         //  330 Maj op = 31, mask = 07FE, xop = 0x042C ( 534) - lwbrx
    { 0x89,  diCMN, 0x042E },         //  331 Maj op = 31, mask = 07FE, xop = 0x042E ( 535) - lfsx
    { 0x89,  diCMN, 0x0430 },         //  332 Maj op = 31, mask = 07FE, xop = 0x0430 ( 536) - srw
    { 0x89,  diCMN, 0x0436 },         //  333 Maj op = 31, mask = 07FE, xop = 0x0436 ( 539) - srd
    { 0x89,  diPRV, 0x046C },         //  334 Maj op = 31, mask = 07FE, xop = 0x046C ( 566) - tlbsync
    { 0x89,  diCMN, 0x046E },         //  335 Maj op = 31, mask = 07FE, xop = 0x046E ( 567) - lfsux
    { 0x89,  diPRV, 0x04A6 },         //  336 Maj op = 31, mask = 07FE, xop = 0x04A6 ( 595) - mfsr
    { 0x89,  diCMN, 0x04AA },         //  337 Maj op = 31, mask = 07FE, xop = 0x04AA ( 597) - lswi
    { 0x89,  diCMN, 0x04AC },         //  338 Maj op = 31, mask = 07FE, xop = 0x04AC ( 598) - sync
    { 0x89,  diCMN, 0x04AE },         //  339 Maj op = 31, mask = 07FE, xop = 0x04AE ( 599) - lfdx
    { 0x89,  diCMN, 0x04EE },         //  340 Maj op = 31, mask = 07FE, xop = 0x04EE ( 631) - lfdux
    { 0x89,  diPRV, 0x0526 },         //  341 Maj op = 31, mask = 07FE, xop = 0x0526 ( 659) - mfsrin
    { 0x89,  diCMN, 0x052A },         //  342 Maj op = 31, mask = 07FE, xop = 0x052A ( 661) - stswx
    { 0x89,  diCMN, 0x052C },         //  343 Maj op = 31, mask = 07FE, xop = 0x052C ( 662) - stwbrx
    { 0x89,  diCMN, 0x052E },         //  344 Maj op = 31, mask = 07FE, xop = 0x052E ( 663) - stfsx
    { 0x89,  diCMN, 0x056E },         //  345 Maj op = 31, mask = 07FE, xop = 0x056E ( 695) - stfsux
    { 0x89,  diCMN, 0x05AA },         //  346 Maj op = 31, mask = 07FE, xop = 0x05AA ( 725) - stswi
    { 0x89,  diCMN, 0x05AE },         //  347 Maj op = 31, mask = 07FE, xop = 0x05AE ( 727) - stfdx
    { 0x89,  diCMN, 0x05EC },         //  348 Maj op = 31, mask = 07FE, xop = 0x05EC ( 758) - dcba
    { 0x89,  diCMN, 0x05EE },         //  349 Maj op = 31, mask = 07FE, xop = 0x05EE ( 759) - stfdux
    { 0x89,  diCMN, 0x062C },         //  350 Maj op = 31, mask = 07FE, xop = 0x062C ( 790) - lhbrx
    { 0x89,  diCMN, 0x0630 },         //  351 Maj op = 31, mask = 07FE, xop = 0x0630 ( 792) - sraw
    { 0x89,  diCMN, 0x0634 },         //  352 Maj op = 31, mask = 07FE, xop = 0x0634 ( 794) - srad
    { 0x89,  diCMN, 0x066C },         //  353 Maj op = 31, mask = 07FE, xop = 0x066C ( 822) - dss
    { 0x89,  diCMN, 0x0670 },         //  354 Maj op = 31, mask = 07FE, xop = 0x0670 ( 824) - srawi
    { 0x89,  diPRV, 0x06A6 },         //  355 Maj op = 31, mask = 07FE, xop = 0x06A6 ( 851) - slbmfev
    { 0x89,  diCMN, 0x06AC },         //  356 Maj op = 31, mask = 07FE, xop = 0x06AC ( 854) - eieio
    { 0x89,  diPRV, 0x0726 },         //  357 Maj op = 31, mask = 07FE, xop = 0x0726 ( 915) - slbmfee
    { 0x89,  diCMN, 0x072C },         //  358 Maj op = 31, mask = 07FE, xop = 0x072C ( 918) - sthbrx
    { 0x89,  diCMN, 0x0734 },         //  359 Maj op = 31, mask = 07FE, xop = 0x0734 ( 922) - extsh
    { 0x89,  diCMN, 0x0774 },         //  360 Maj op = 31, mask = 07FE, xop = 0x0774 ( 954) - extsb
    { 0x89,  diCMN, 0x07AC },         //  361 Maj op = 31, mask = 07FE, xop = 0x07AC ( 982) - icbi
    { 0x89,  diCMN, 0x07AE },         //  362 Maj op = 31, mask = 07FE, xop = 0x07AE ( 983) - stfiwx
    { 0x89,  diCMN, 0x07B4 },         //  363 Maj op = 31, mask = 07FE, xop = 0x07B4 ( 986) - extsw
    { 0x09,  diCMN, 0x07EC },         //  364 Maj op = 31, mask = 07FE, xop = 0x07EC (1014) - dcbz
    { 0x81,  diCMN, 0x0000 },         //  365 Maj op = 58, mask = 0003, xop = 0x0000 (   0) - ld
    { 0x81,  diCMN, 0x0001 },         //  366 Maj op = 58, mask = 0003, xop = 0x0001 (   1) - ldu
    { 0x01,  diCMN, 0x0002 },         //  367 Maj op = 58, mask = 0003, xop = 0x0002 (   2) - lwa
    { 0x84,  diCMN, 0x0024 },         //  368 Maj op = 59, mask = 003E, xop = 0x0024 (  18) - fdivs
    { 0x84,  diCMN, 0x0028 },         //  369 Maj op = 59, mask = 003E, xop = 0x0028 (  20) - fsubs
    { 0x84,  diCMN, 0x002A },         //  370 Maj op = 59, mask = 003E, xop = 0x002A (  21) - fadds
    { 0x84,  diCMN, 0x002C },         //  371 Maj op = 59, mask = 003E, xop = 0x002C (  22) - fsqrts
    { 0x84,  diCMN, 0x0030 },         //  372 Maj op = 59, mask = 003E, xop = 0x0030 (  24) - fres
    { 0x84,  diCMN, 0x0032 },         //  373 Maj op = 59, mask = 003E, xop = 0x0032 (  25) - fmuls
    { 0x84,  diCMN, 0x0038 },         //  374 Maj op = 59, mask = 003E, xop = 0x0038 (  28) - fmsubs
    { 0x84,  diCMN, 0x003A },         //  375 Maj op = 59, mask = 003E, xop = 0x003A (  29) - fmadds
    { 0x84,  diCMN, 0x003C },         //  376 Maj op = 59, mask = 003E, xop = 0x003C (  30) - fnmsubs
    { 0x04,  diCMN, 0x003E },         //  377 Maj op = 59, mask = 003E, xop = 0x003E (  31) - fnmadds
    { 0x81,  diCMN, 0x0000 },         //  378 Maj op = 62, mask = 0003, xop = 0x0000 (   0) - std
    { 0x01,  diCMN, 0x0001 },         //  379 Maj op = 62, mask = 0003, xop = 0x0001 (   1) - stdu
    { 0x84,  diCMN, 0x0024 },         //  380 Maj op = 63, mask = 003E, xop = 0x0024 (  18) - fdiv
    { 0x84,  diCMN, 0x0028 },         //  381 Maj op = 63, mask = 003E, xop = 0x0028 (  20) - fsub
    { 0x84,  diCMN, 0x002A },         //  382 Maj op = 63, mask = 003E, xop = 0x002A (  21) - fadd
    { 0x84,  diCMN, 0x002C },         //  383 Maj op = 63, mask = 003E, xop = 0x002C (  22) - fsqrt
    { 0x84,  diCMN, 0x002E },         //  384 Maj op = 63, mask = 003E, xop = 0x002E (  23) - fsel
    { 0x84,  diCMN, 0x0032 },         //  385 Maj op = 63, mask = 003E, xop = 0x0032 (  25) - fmul
    { 0x84,  diCMN, 0x0034 },         //  386 Maj op = 63, mask = 003E, xop = 0x0034 (  26) - frsqrte
    { 0x84,  diCMN, 0x0038 },         //  387 Maj op = 63, mask = 003E, xop = 0x0038 (  28) - fmsub
    { 0x84,  diCMN, 0x003A },         //  388 Maj op = 63, mask = 003E, xop = 0x003A (  29) - fmadd
    { 0x84,  diCMN, 0x003C },         //  389 Maj op = 63, mask = 003E, xop = 0x003C (  30) - fnmsub
    { 0x84,  diCMN, 0x003E },         //  390 Maj op = 63, mask = 003E, xop = 0x003E (  31) - fnmadd
    { 0x89,  diCMN, 0x0000 },         //  391 Maj op = 63, mask = 07FE, xop = 0x0000 (   0) - fcmpu
    { 0x89,  diCMN, 0x0018 },         //  392 Maj op = 63, mask = 07FE, xop = 0x0018 (  12) - frsp
    { 0x89,  diCMN, 0x001C },         //  393 Maj op = 63, mask = 07FE, xop = 0x001C (  14) - fctiw
    { 0x89,  diCMN, 0x001E },         //  394 Maj op = 63, mask = 07FE, xop = 0x001E (  15) - fctiwz
    { 0x89,  diCMN, 0x0040 },         //  395 Maj op = 63, mask = 07FE, xop = 0x0040 (  32) - fcmpo
    { 0x89,  diCMN, 0x004C },         //  396 Maj op = 63, mask = 07FE, xop = 0x004C (  38) - mtfsb1
    { 0x89,  diCMN, 0x0050 },         //  397 Maj op = 63, mask = 07FE, xop = 0x0050 (  40) - fneg
    { 0x89,  diCMN, 0x0080 },         //  398 Maj op = 63, mask = 07FE, xop = 0x0080 (  64) - mcrfs
    { 0x89,  diCMN, 0x008C },         //  399 Maj op = 63, mask = 07FE, xop = 0x008C (  70) - mtfsb0
    { 0x89,  diCMN, 0x0090 },         //  400 Maj op = 63, mask = 07FE, xop = 0x0090 (  72) - fmr
    { 0x89,  diCMN, 0x010C },         //  401 Maj op = 63, mask = 07FE, xop = 0x010C ( 134) - mtfsfi
    { 0x89,  diCMN, 0x0110 },         //  402 Maj op = 63, mask = 07FE, xop = 0x0110 ( 136) - fnabs
    { 0x89,  diCMN, 0x0210 },         //  403 Maj op = 63, mask = 07FE, xop = 0x0210 ( 264) - fabs
    { 0x89,  diCMN, 0x048E },         //  404 Maj op = 63, mask = 07FE, xop = 0x048E ( 583) - mffs
    { 0x89,  diCMN, 0x058E },         //  405 Maj op = 63, mask = 07FE, xop = 0x058E ( 711) - mtfsf
    { 0x89,  diCMN, 0x065C },         //  406 Maj op = 63, mask = 07FE, xop = 0x065C ( 814) - fctid
    { 0x89,  diCMN, 0x065E },         //  407 Maj op = 63, mask = 07FE, xop = 0x065E ( 815) - fctidz
    { 0x09,  diCMN, 0x069C },         //  408 Maj op = 63, mask = 07FE, xop = 0x069C ( 846) - fcfid
};

#ifdef __decodePPC_debug__
char *instname[] = {
    "Jump entry...",
    "Invalid",
    "tdi",
    "twi",
    "Jump entry...",
    "Invalid",
    "Invalid",
    "mulli",
    "subfic",
    "Invalid",
    "cmpli",
    "cmpi",
    "addic",
    "addic.",
    "addi",
    "addis",
    "bc",
    "sc",
    "b",
    "Jump entry...",
    "rlwimi",
    "rlwinm",
    "Invalid",
    "rlwnm",
    "ori",
    "oris",
    "xori",
    "xoris",
    "andi.",
    "andis.",
    "Jump entry...",
    "Jump entry...",
    "lwz",
    "lwzu",
    "lbz",
    "lbzu",
    "stw",
    "stwu",
    "stb",
    "stbu",
    "lhz",
    "lhzu",
    "lha",
    "lhau",
    "sth",
    "sthu",
    "lmw",
    "stmw",
    "lfs",
    "lfsu",
    "lfd",
    "lfdu",
    "stfs",
    "stfsu",
    "stfd",
    "stfdu",
    "Invalid",
    "Invalid",
    "Jump entry...",
    "Jump entry...",
    "Invalid",
    "Invalid",
    "Jump entry...",
    "Jump entry...",
    "attn",
    "vmhaddshs",
    "vmhraddshs",
    "vmladduhm",
    "vmsumubm",
    "vmsummbm",
    "vmsumuhm",
    "vmsumuhs",
    "vmsumshm",
    "vmsumshs",
    "vsel",
    "vperm",
    "vsldoi",
    "vmaddfp",
    "vnmsubfp",
    "vcmpequb",
    "vcmpequh",
    "vcmpequw",
    "vcmpeqfp",
    "vcmpgefp",
    "vcmpgtub",
    "vcmpgtuh",
    "vcmpgtuw",
    "vcmpgtfp",
    "vcmpgtsb",
    "vcmpgtsh",
    "vcmpgtsw",
    "vcmpbfp",
    "vaddubm",
    "vmaxub",
    "vrlb",
    "vmuloub",
    "vaddfp",
    "vmrghb",
    "vpkuhum",
    "vadduhm",
    "vmaxuh",
    "vrlh",
    "vmulouh",
    "vsubfp",
    "vmrghh",
    "vpkuwum",
    "vadduwm",
    "vmaxuw",
    "vrlw",
    "vmrghw",
    "vpkuhus",
    "vpkuwus",
    "vmaxsb",
    "vslb",
    "vmulosb",
    "vrefp",
    "vmrglb",
    "vpkshus",
    "vmaxsh",
    "vslh",
    "vmulosh",
    "vrsqrtefp",
    "vmrglh",
    "vpkswus",
    "vaddcuw",
    "vmaxsw",
    "vslw",
    "vexptefp",
    "vmrglw",
    "vpkshss",
    "vsl",
    "vlogefp",
    "vpkswss",
    "vaddubs",
    "vminub",
    "vsrb",
    "vmuleub",
    "vrfin",
    "vspltb",
    "vupkhsb",
    "vadduhs",
    "vminuh",
    "vsrh",
    "vmuleuh",
    "vrfiz",
    "vsplth",
    "vupkhsh",
    "vadduws",
    "vminuw",
    "vsrw",
    "vrfip",
    "vspltw",
    "vupklsb",
    "vsr",
    "vrfim",
    "vupklsh",
    "vaddsbs",
    "vminsb",
    "vsrab",
    "vmulesb",
    "vcfux",
    "vspltisb",
    "vpkpx",
    "vaddshs",
    "vminsh",
    "vsrah",
    "vmulesh",
    "vcfsx",
    "vspltish",
    "vupkhpx",
    "vaddsws",
    "vminsw",
    "vsraw",
    "vctuxs",
    "vspltisw",
    "vctsxs",
    "vupklpx",
    "vsububm",
    "vavgub",
    "vand",
    "vmaxfp",
    "vslo",
    "vsubuhm",
    "vavguh",
    "vandc",
    "vminfp",
    "vsro",
    "vsubuwm",
    "vavguw",
    "vor",
    "vxor",
    "vavgsb",
    "vnor",
    "vavgsh",
    "vsubcuw",
    "vavgsw",
    "vsububs",
    "mfvscr",
    "vsum4ubs",
    "vsubuhs",
    "mtvscr",
    "vsum4shs",
    "vsubuws",
    "vsum2sws",
    "vsubsbs",
    "vsum4sbs",
    "vsubshs",
    "vsubsws",
    "vsumsws",
    "mcrf",
    "bclr",
    "rfid",
    "crnor",
    "rfi",
    "crandc",
    "isync",
    "crxor",
    "crnand",
    "crand",
    "hrfid",
    "creqv",
    "crorc",
    "cror",
    "bctr",
    "rldicl",
    "rldicr",
    "rldic",
    "rldimi",
    "rldcl",
    "rldcr",
    "subfc",
    "mulhdu",
    "addc",
    "mulhwu",
    "subf",
    "mulhd",
    "mulhw",
    "neg",
    "subfe",
    "adde",
    "subfze",
    "addze",
    "subfme",
    "mulld",
    "addme",
    "mullw",
    "add",
    "divdu",
    "divwu",
    "divd",
    "divw",
    "sradi",
    "cmp",
    "tw",
    "lvsl",
    "lvebx",
    "mfcr",
    "lwarx",
    "ldx",
    "lwzx",
    "slw",
    "cntlzw",
    "sld",
    "and",
    "cmpl",
    "lvsr",
    "lvehx",
    "ldux",
    "dcbst",
    "lwzux",
    "cntlzd",
    "andc",
    "td",
    "lvewx",
    "mfmsr",
    "ldarx",
    "dcbf",
    "lbzx",
    "lvx",
    "lbzux",
    "nor",
    "stvebx",
    "mtcrf",
    "mtmsr",
    "stdx",
    "stwcx",
    "stwx",
    "stvehx",
    "mtmsrd",
    "stdux",
    "stwux",
    "stvewx",
    "mtsr",
    "stdcx.",
    "stbx",
    "stvx",
    "mtsrin",
    "dcbtst",
    "stbux",
    "tlbiel",
    "dcbt",
    "lhzx",
    "eqv",
    "tlbie",
    "eciwx",
    "lhzux",
    "xor",
    "mfspr",
    "lwax",
    "dst",
    "lhax",
    "lvxl",
    "tlbia",
    "mftb",
    "lwaux",
    "dstst",
    "lhaux",
    "slbmte",
    "sthx",
    "orc",
    "slbie",
    "ecowx",
    "sthux",
    "or",
    "mtspr",
    "nand",
    "stvxl",
    "slbia",
    "mcrxr",
    "lswx",
    "lwbrx",
    "lfsx",
    "srw",
    "srd",
    "tlbsync",
    "lfsux",
    "mfsr",
    "lswi",
    "sync",
    "lfdx",
    "lfdux",
    "mfsrin",
    "stswx",
    "stwbrx",
    "stfsx",
    "stfsux",
    "stswi",
    "stfdx",
    "dcba",
    "stfdux",
    "lhbrx",
    "sraw",
    "srad",
    "dss",
    "srawi",
    "slbmfev",
    "eieio",
    "slbmfee",
    "sthbrx",
    "extsh",
    "extsb",
    "icbi",
    "stfiwx",
    "extsw",
    "dcbz",
    "ld",
    "ldu",
    "lwa",
    "fdivs",
    "fsubs",
    "fadds",
    "fsqrts",
    "fres",
    "fmuls",
    "fmsubs",
    "fmadds",
    "fnmsubs",
    "fnmadds",
    "std",
    "stdu",
    "fdiv",
    "fsub",
    "fadd",
    "fsqrt",
    "fsel",
    "fmul",
    "frsqrte",
    "fmsub",
    "fmadd",
    "fnmsub",
    "fnmadd",
    "fcmpu",
    "frsp",
    "fctiw",
    "fctiwz",
    "fcmpo",
    "mtfsb1",
    "fneg",
    "mcrfs",
    "mtfsb0",
    "fmr",
    "mtfsfi",
    "fnabs",
    "fabs",
    "mffs",
    "mtfsf",
    "fctid",
    "fctidz",
    "fcfid",
};
#endif

static dcdtab dcdfail = { 0x00,	 diINV, 0x0000 };	// Decode failed

static uint32_t sprtbl[] = {
    0xCCC03274,						// spr    0 to   31
    0x00000000,						// spr   32 to   63
    0x00000000,						// spr   64 to   95
    0x00000000,						// spr   96 to  127
    0x00000080,						// spr  128 to  159
    0x00000000,						// spr  160 to  191
    0x00000000,						// spr  192 to  223
    0x00000000,						// spr  224 to  255
    0x9000FCAD,						// spr  256 to  287
    0x0000C3F3,						// spr  288 to  319
    0x00000000,						// spr  320 to  351
    0x00000000,						// spr  352 to  383
    0x00000000,						// spr  384 to  415
    0x00000000,						// spr  416 to  447
    0x00000000,						// spr  448 to  479
    0x00000000,						// spr  480 to  511
    0x0000FFFF,						// spr  512 to  543
    0x00000000,						// spr  544 to  575
    0x00000000,						// spr  576 to  607
    0x00000000,						// spr  608 to  639
    0x00000000,						// spr  640 to  671
    0x00000000,						// spr  672 to  703
    0x00000000,						// spr  704 to  735
    0x00000000,						// spr  736 to  767
    0x3FFF3FFF,						// spr  768 to  799
    0x00000000,						// spr  800 to  831
    0x00000000,						// spr  832 to  863
    0x00000000,						// spr  864 to  895
    0x00000000,						// spr  896 to  927
    0xE1FFE1FF,						// spr  928 to  959
    0x0000FE80,						// spr  960 to  991
    0x0000FFFF,						// spr  992 to 1023
};
