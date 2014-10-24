/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>

/* Function to efficiently compute cube root */

float cbrtf(float x);

struct cbrt_table_entry {
        double x;
        double cbrt_x;
        double recip_cbrt_x;
        double recip_x;
};

static const struct cbrt_table_entry cbrt_table[] = {
        /* mantissa = 0x1.00... */
        {0x1.0000000000000p+0, 0x1.0000000000000p+0,
        0x1.0000000000000p+0, 0x1.0000000000000p+0}, /* exponent = 0 */
        {0x1.037e200000000p+1, 0x1.4400000000000p+0,
        0x1.948b0fcd6e9e0p-1, 0x1.f91bd1b62b9cfp-2}, /* exponent = 1 */
        {0x1.0315800000000p+2, 0x1.9800000000000p+0,
        0x1.4141414141414p-1, 0x1.f9e7cba5753afp-3}, /* exponent = 2 */

        /* mantissa = 0x1.04... */
        {0x1.060c080000000p+0, 0x1.0200000000000p+0,
        0x1.fc07f01fc07f0p-1, 0x1.f42f61dacddc6p-1}, /* exponent = 0 */
        {0x1.05ff4c356ff40p+1, 0x1.450a000000000p+0,
        0x1.933fff9b30002p-1, 0x1.f447b132ca3acp-2}, /* exponent = 1 */
        {0x1.06e9aa0000000p+2, 0x1.9a00000000000p+0,
        0x1.3fb013fb013fbp-1, 0x1.f289bb31fd41cp-3}, /* exponent = 2 */

        /* mantissa = 0x1.08...*/
        {0x1.09fe97c0b2e80p+0, 0x1.034a000000000p+0,
        0x1.f9815c85b04a3p-1, 0x1.ecc3168ac46e4p-1}, // exponent = 0
        {0x1.0853ec0000000p+1, 0x1.4600000000000p+0, 0x1.920fb49d0e229p-1, 0x1.efde7dcdacefdp-2}, // exponent = 1
        {0x1.0ac7700000000p+2, 0x1.9c00000000000p+0, 0x1.3e22cbce4a902p-1, 0x1.eb501ca81bb3ep-3}, // exponent = 2

        /* mantissa = 0x1.0c...*/
        {0x1.0c30400000000p+0, 0x1.0400000000000p+0, 0x1.f81f81f81f820p-1, 0x1.e8bb1d5b6e585p-1}, // exponent = 0
        {0x1.0d39000000000p+1, 0x1.4800000000000p+0, 0x1.8f9c18f9c18fap-1, 0x1.e6da80ced1523p-2}, // exponent = 1
        {0x1.0eaede0000000p+2, 0x1.9e00000000000p+0, 0x1.3c995a47babe7p-1, 0x1.e43a0fc24fe4bp-3}, // exponent = 2

        /* mantissa = 0x1.10...*/
        {0x1.126cd80000000p+0, 0x1.0600000000000p+0, 0x1.f44659e4a4271p-1, 0x1.dd9fb30af3365p-1}, // exponent = 0
        {0x1.122d740000000p+1, 0x1.4a00000000000p+0, 0x1.8d3018d3018d3p-1, 0x1.de0e209af882ep-2}, // exponent = 1
        {0x1.12a0000000000p+2, 0x1.a000000000000p+0, 0x1.3b13b13b13b14p-1, 0x1.dd46baab49c24p-3}, // exponent = 2

        /* mantissa = 0x1.14...*/
        {0x1.15f9b5b480000p+0, 0x1.0720000000000p+0, 0x1.f222c82dba316p-1, 0x1.d786108fd7a9fp-1}, // exponent = 0
        {0x1.1731600000000p+1, 0x1.4c00000000000p+0, 0x1.8acb90f6bf3aap-1, 0x1.d577b2f5c6f87p-2}, // exponent = 1
        {0x1.169ae20000000p+2, 0x1.a200000000000p+0, 0x1.3991c2c187f63p-1, 0x1.d67549c6f9b67p-3}, // exponent = 2

        /* mantissa = 0x1.18...*/
        {0x1.18c2000000000p+0, 0x1.0800000000000p+0, 0x1.f07c1f07c1f08p-1, 0x1.d2d9cbd756afdp-1}, // exponent = 0
        {0x1.19fb2ce620540p+1, 0x1.4d1a000000000p+0, 0x1.897d564f5cf98p-1, 0x1.d0d34ccd78141p-2}, // exponent = 1
        {0x1.1a9f900000000p+2, 0x1.a400000000000p+0, 0x1.3813813813814p-1, 0x1.cfc4ef7db5bffp-3}, // exponent = 2

        /* mantissa = 0x1.1c...*/
        {0x1.1f2fe80000000p+0, 0x1.0a00000000000p+0, 0x1.ecc07b301ecc0p-1, 0x1.c86636f753a66p-1}, // exponent = 0
        {0x1.1c44dc0000000p+1, 0x1.4e00000000000p+0, 0x1.886e5f0abb04ap-1, 0x1.cd159cdbba714p-2}, // exponent = 1
        {0x1.1eae160000000p+2, 0x1.a600000000000p+0, 0x1.3698df3de0748p-1, 0x1.c934e4095d202p-3}, // exponent = 2

        /* mantissa = 0x1.20...*/
        {0x1.21fac7ca59c00p+0, 0x1.0adc000000000p+0, 0x1.eb2a412496abdp-1, 0x1.c40112c606d3ep-1}, // exponent = 0
        {0x1.2168000000000p+1, 0x1.5000000000000p+0, 0x1.8618618618618p-1, 0x1.c4e651e0c37d7p-2}, // exponent = 1
        {0x1.22c6800000000p+2, 0x1.a800000000000p+0, 0x1.3521cfb2b78c1p-1, 0x1.c2c46544650c1p-3}, // exponent = 2

        /* mantissa = 0x1.24...*/
        {0x1.25b6c00000000p+0, 0x1.0c00000000000p+0, 0x1.e9131abf0b767p-1, 0x1.be41e7ee3f7edp-1}, // exponent = 0
        {0x1.269ae40000000p+1, 0x1.5200000000000p+0, 0x1.83c977ab2beddp-1, 0x1.bce853967753cp-2}, // exponent = 1
        {0x1.26e8da0000000p+2, 0x1.aa00000000000p+0, 0x1.33ae45b57bcb2p-1, 0x1.bc72b67ab9ce7p-3}, // exponent = 2

        /* mantissa = 0x1.28...*/
        {0x1.29ff9aaaa2c00p+0, 0x1.0d4c000000000p+0, 0x1.e6b8275501adbp-1, 0x1.b7d7596e80007p-1}, // exponent = 0
        {0x1.2bdda00000000p+1, 0x1.5400000000000p+0, 0x1.8181818181818p-1, 0x1.b51a30f9739f8p-2}, // exponent = 1
        {0x1.2b15300000000p+2, 0x1.ac00000000000p+0, 0x1.323e34a2b10bfp-1, 0x1.b63f203c60c07p-3}, // exponent = 2

        /* mantissa = 0x1.2c...*/
        {0x1.2c56b80000000p+0, 0x1.0e00000000000p+0, 0x1.e573ac901e574p-1, 0x1.b469f4adc7794p-1}, // exponent = 0
        {0x1.2dfff74f29dc0p+1, 0x1.54ce000000000p+0, 0x1.80987c755886ap-1, 0x1.b203708429799p-2}, // exponent = 1
        {0x1.2f4b8e0000000p+2, 0x1.ae00000000000p+0, 0x1.30d190130d190p-1, 0x1.b028f031c8644p-3}, // exponent = 2

        /* mantissa = 0x1.30...*/
        {0x1.3310000000000p+0, 0x1.1000000000000p+0, 0x1.e1e1e1e1e1e1ep-1, 0x1.aadb93d39ae9cp-1}, // exponent = 0
        {0x1.31304c0000000p+1, 0x1.5600000000000p+0, 0x1.7f405fd017f40p-1, 0x1.ad7a85e593e54p-2}, // exponent = 1
        {0x1.338c000000000p+2, 0x1.b000000000000p+0, 0x1.2f684bda12f68p-1, 0x1.aa2f78f1b4cc6p-3}, // exponent = 2

        /* mantissa = 0x1.34... */
        {0x1.35fb6f4579c00p+0, 0x1.10dc000000000p+0, 0x1.e05d5a24448c5p-1, 0x1.a6d6548fa984dp-1}, // exponent = 0
        {0x1.3693000000000p+1, 0x1.5800000000000p+0, 0x1.7d05f417d05f4p-1, 0x1.a607fa909db1fp-2}, // exponent = 1
        {0x1.37d6920000000p+2, 0x1.b200000000000p+0, 0x1.2e025c04b8097p-1, 0x1.a45211d8b748ap-3}, // exponent = 2

/* mantissa = 0x1.38... */
        {0x1.39e2c80000000p+0, 0x1.1200000000000p+0, 0x1.de5d6e3f8868ap-1, 0x1.a1941b013022dp-1}, // exponent = 0
        {0x1.39fe541ac7840p+1, 0x1.5942000000000p+0, 0x1.7ba298eae8947p-1, 0x1.a16f787114257p-2}, // exponent = 1
        {0x1.39ffaac000000p+2, 0x1.b300000000000p+0, 0x1.2d50a012d50a0p-1, 0x1.a16db0ec408b2p-3}, // exponent = 2

        /* mantissa = 0x1.3c... */
        {0x1.3dfc1312b0000p+0, 0x1.1330000000000p+0, 0x1.dc4cfaf10eb5cp-1, 0x1.9c322b87f17e8p-1}, // exponent = 0
        {0x1.3c05d40000000p+1, 0x1.5a00000000000p+0, 0x1.7ad2208e0ecc3p-1, 0x1.9ec1430b0dfc7p-2}, // exponent = 1
        {0x1.3c2b500000000p+2, 0x1.b400000000000p+0, 0x1.2c9fb4d812ca0p-1, 0x1.9e9016e2211b6p-3}, // exponent = 2

        /* mantissa = 0x1.40... */
        {0x1.40cf400000000p+0, 0x1.1400000000000p+0, 0x1.dae6076b981dbp-1, 0x1.9890fd4bf368fp-1}, // exponent = 0
        {0x1.4188e00000000p+1, 0x1.5c00000000000p+0, 0x1.78a4c8178a4c8p-1, 0x1.97a51ec6b707ep-2}, // exponent = 1
        {0x1.408a460000000p+2, 0x1.b600000000000p+0, 0x1.2b404ad012b40p-1, 0x1.98e8e88261b62p-3}, // exponent = 2

        /* mantissa = 0x1.44... */
        {0x1.47d5980000000p+0, 0x1.1600000000000p+0, 0x1.d77b654b82c34p-1, 0x1.8fcfc9c44e2f4p-1}, // exponent = 0
        {0x1.471c3c0000000p+1, 0x1.5e00000000000p+0, 0x1.767dce434a9b1p-1, 0x1.90b25822e2a9fp-2}, // exponent = 1
        {0x1.44f3800000000p+2, 0x1.b800000000000p+0, 0x1.29e4129e4129ep-1, 0x1.935beb82c1ae7p-3}, // exponent = 2

        /* mantissa = 0x1.48... */
        {0x1.49feb2bc0dc00p+0, 0x1.169c000000000p+0, 0x1.d67366d6ddfd0p-1, 0x1.8d31a9f2d47fbp-1}, // exponent = 0
        {0x1.49fcfb130a6c0p+1, 0x1.5f06000000000p+0, 0x1.75664a1a72c8dp-1, 0x1.8d33bb2686480p-2}, // exponent = 1
        {0x1.49670a0000000p+2, 0x1.ba00000000000p+0, 0x1.288b01288b013p-1, 0x1.8de888de6c48fp-3}, // exponent = 2

        /* mantissa = 0x1.4c... */
        {0x1.4ef6000000000p+0, 0x1.1800000000000p+0, 0x1.d41d41d41d41dp-1, 0x1.874e2a121159fp-1}, // exponent = 0
        {0x1.4cc0000000000p+1, 0x1.6000000000000p+0, 0x1.745d1745d1746p-1, 0x1.89e7c3fdb1246p-2}, // exponent = 1
        {0x1.4de4f00000000p+2, 0x1.bc00000000000p+0, 0x1.27350b8812735p-1, 0x1.888e2da0ba19dp-3}, // exponent = 2

        /* mantissa = 0x1.50... */
        {0x1.51ff889bc6000p+0, 0x1.18d8000000000p+0, 0x1.d2b539aeee152p-1, 0x1.83ca00a5a8f32p-1}, // exponent = 0
        {0x1.5274440000000p+1, 0x1.6200000000000p+0, 0x1.724287f46debcp-1, 0x1.8344414a70cbdp-2}, // exponent = 1
        {0x1.526d3e0000000p+2, 0x1.be00000000000p+0, 0x1.25e22708092f1p-1, 0x1.834c4ac4afd3bp-3}, // exponent = 2

        /* mantissa = 0x1.54... */
        {0x1.5630a80000000p+0, 0x1.1a00000000000p+0, 0x1.d0cb58f6ec074p-1, 0x1.7f09e124e78b8p-1}, // exponent = 0
        {0x1.55fc05a5df140p+1, 0x1.633a000000000p+0, 0x1.70fb3e12b41c4p-1, 0x1.7f44d50c76c8ep-2}, // exponent = 1
        {0x1.5700000000000p+2, 0x1.c000000000000p+0, 0x1.2492492492492p-1, 0x1.7e225515a4f1dp-3}, // exponent = 2

        /* mantissa = 0x1.58... */
        {0x1.59fc8db9a7e80p+0, 0x1.1b0a000000000p+0, 0x1.cf1688b3b4e6ap-1, 0x1.7ad5e68ed5f8cp-1}, // exponent = 0
        {0x1.5839200000000p+1, 0x1.6400000000000p+0, 0x1.702e05c0b8170p-1, 0x1.7cc6b8acae7cbp-2}, // exponent = 1
        {0x1.5b9d420000000p+2, 0x1.c200000000000p+0, 0x1.23456789abcdfp-1, 0x1.790fc51106751p-3}, // exponent = 2

        /* mantissa = 0x1.5c... */
        {0x1.5d85c00000000p+0, 0x1.1c00000000000p+0, 0x1.cd85689039b0bp-1, 0x1.7700c9f78cc63p-1}, // exponent = 0
        {0x1.5e0eac0000000p+1, 0x1.6600000000000p+0, 0x1.6e1f76b4337c7p-1, 0x1.766e1c17c26ecp-2}, // exponent = 1
        {0x1.5dfdce5811360p+2, 0x1.c306000000000p+0, 0x1.229c346a04441p-1, 0x1.7680273c586edp-3}, // exponent = 2

        /* mantissa = 0x1.60... */
        {0x1.61fbc0c515400p+0, 0x1.1d34000000000p+0, 0x1.cb92ff3a86d65p-1, 0x1.7246f92d40d4cp-1}, // exponent = 0
        {0x1.63f5000000000p+1, 0x1.6800000000000p+0, 0x1.6c16c16c16c17p-1, 0x1.70396672a04e5p-2}, // exponent = 1
        {0x1.6045100000000p+2, 0x1.c400000000000p+0, 0x1.21fb78121fb78p-1, 0x1.741416c92a70bp-3}, // exponent = 2

        /* mantissa = 0x1.64... */
        {0x1.64f5780000000p+0, 0x1.1e00000000000p+0, 0x1.ca4b3055ee191p-1, 0x1.6f30d6649f11bp-1}, // exponent = 0
        {0x1.65fa1cdfa11c0p+1, 0x1.68ae000000000p+0, 0x1.6b671c62a2d0ap-1, 0x1.6e257c2026aefp-2}, // exponent = 1
        {0x1.64f7760000000p+2, 0x1.c600000000000p+0, 0x1.20b470c67c0d9p-1, 0x1.6f2ec9c929a29p-3}, // exponent = 2

        /* mantissa = 0x1.68... */
        {0x1.69fc04b688980p+0, 0x1.1f56000000000p+0, 0x1.c829b51036037p-1, 0x1.6a17c8a1a662ep-1}, // exponent = 0
        {0x1.69ec340000000p+1, 0x1.6a00000000000p+0, 0x1.6a13cd1537290p-1, 0x1.6a279b3fb4a4ep-2}, // exponent = 1
        {0x1.69b4800000000p+2, 0x1.c800000000000p+0, 0x1.1f7047dc11f70p-1, 0x1.6a5f60f9b4c97p-3}, // exponent = 2

        /* mantissa = 0x1.6c... */
        {0x1.6c80000000000p+0, 0x1.2000000000000p+0, 0x1.c71c71c71c71cp-1, 0x1.67980e0bf08c7p-1}, // exponent = 0
        {0x1.6ff4600000000p+1, 0x1.6c00000000000p+0, 0x1.6816816816817p-1, 0x1.6437c6489c8e0p-2}, // exponent = 1
        {0x1.6e7c3a0000000p+2, 0x1.ca00000000000p+0, 0x1.1e2ef3b3fb874p-1, 0x1.65a56286dbe08p-3}, // exponent = 2

        /* mantissa = 0x1.70... */
        {0x1.71fc3c5870000p+0, 0x1.2170000000000p+0, 0x1.c4d9cd40d7cfdp-1, 0x1.6243421ae7a84p-1}, // exponent = 0
        {0x1.71fef1bff2600p+1, 0x1.6cac000000000p+0, 0x1.676caae4b2e0fp-1, 0x1.6240aa2fa0dfdp-2}, // exponent = 1
        {0x1.734eb00000000p+2, 0x1.cc00000000000p+0, 0x1.1cf06ada2811dp-1, 0x1.610057c6bdd38p-3}, // exponent = 2

        /* mantissa = 0x1.74... */
        {0x1.7425880000000p+0, 0x1.2200000000000p+0, 0x1.c3f8f01c3f8f0p-1, 0x1.60348d4756756p-1}, // exponent = 0
        {0x1.760d9c0000000p+1, 0x1.6e00000000000p+0, 0x1.661ec6a5122f9p-1, 0x1.5e68fb4d877a7p-2}, // exponent = 1
        {0x1.75fb34f0902a0p+2, 0x1.cd1a000000000p+0, 0x1.1c4227955e4f1p-1, 0x1.5e7a396f89f71p-3}, // exponent = 2

        /* mantissa = 0x1.78... */
        {0x1.7be6400000000p+0, 0x1.2400000000000p+0, 0x1.c0e070381c0e0p-1, 0x1.5904842e0271bp-1}, // exponent = 0
        {0x1.79fec8fa79000p+1, 0x1.6f48000000000p+0, 0x1.64def50b37b22p-1, 0x1.5ac1740057116p-2}, // exponent = 1
        {0x1.782bee0000000p+2, 0x1.ce00000000000p+0, 0x1.1bb4a4046ed29p-1, 0x1.5c6fcd2117a65p-3}, // exponent = 2

        /* mantissa = 0x1.7c... */
        {0x1.7dfa08e162000p+0, 0x1.2488000000000p+0, 0x1.c00fc08dc4fbfp-1, 0x1.57242f8b50298p-1}, // exponent = 0
        {0x1.7c38000000000p+1, 0x1.7000000000000p+0, 0x1.642c8590b2164p-1, 0x1.58ba55b815609p-2}, // exponent = 1
        {0x1.7d14000000000p+2, 0x1.d000000000000p+0, 0x1.1a7b9611a7b96p-1, 0x1.57f351f7aa6eap-3}, // exponent = 2

        /* mantissa = 0x1.80... */
        {0x1.83c2580000000p+0, 0x1.2600000000000p+0, 0x1.bdd2b899406f7p-1, 0x1.520635a583b96p-1}, // exponent = 0
        {0x1.8273a40000000p+1, 0x1.7200000000000p+0, 0x1.623fa77016240p-1, 0x1.532af851862acp-2}, // exponent = 1
        {0x1.8206f20000000p+2, 0x1.d200000000000p+0, 0x1.19453808ca29cp-1, 0x1.538a788f6fdd6p-3}, // exponent = 2

        /* mantissa = 0x1.84... */
        {0x1.85fd33ff90000p+0, 0x1.2690000000000p+0, 0x1.bcf8c69606a07p-1, 0x1.50176a58004f0p-1}, // exponent = 0
        {0x1.85fccde240000p+1, 0x1.7320000000000p+0, 0x1.612cc01b977f0p-1, 0x1.5017c2589970ep-2}, // exponent = 1
        {0x1.8704d00000000p+2, 0x1.d400000000000p+0, 0x1.1811811811812p-1, 0x1.4f34d5fa956d6p-3}, // exponent = 2

        /* mantissa = 0x1.88... */
        {0x1.8bba000000000p+0, 0x1.2800000000000p+0, 0x1.bacf914c1bad0p-1, 0x1.4b37f67f9d05cp-1}, // exponent = 0
        {0x1.88c0a00000000p+1, 0x1.7400000000000p+0, 0x1.6058160581606p-1, 0x1.4dba0cfc11861p-2}, // exponent = 1
        {0x1.89fbb1ca4e0e0p+2, 0x1.d52e000000000p+0, 0x1.175d3b160af03p-1, 0x1.4caf2b205f9ddp-3}, // exponent = 2

        /* mantissa = 0x1.8c... */
        {0x1.8dfca52590000p+0, 0x1.2890000000000p+0, 0x1.b9f88e001b9f9p-1, 0x1.495664ea7f47dp-1}, // exponent = 0
        {0x1.8f1f0c0000000p+1, 0x1.7600000000000p+0, 0x1.5e75bb8d015e7p-1, 0x1.4866c46f405dbp-2}, // exponent = 1
        {0x1.8c0da60000000p+2, 0x1.d600000000000p+0, 0x1.16e0689427379p-1, 0x1.4af2020336a59p-3}, // exponent = 2

        /* mantissa = 0x1.90... */
        {0x1.93cd680000000p+0, 0x1.2a00000000000p+0, 0x1.b7d6c3dda338bp-1, 0x1.44982ca42a2ebp-1}, // exponent = 0
        {0x1.91fabaf07d200p+1, 0x1.76e4000000000p+0, 0x1.5da09741396f7p-1, 0x1.461102bc1cb8fp-2}, // exponent = 1
        {0x1.9121800000000p+2, 0x1.d800000000000p+0, 0x1.15b1e5f75270dp-1, 0x1.46c19716cf2c0p-3}, // exponent = 2

        /* mantissa = 0x1.94... */
        {0x1.95ff68a951e80p+0, 0x1.2a8a000000000p+0, 0x1.b70b72f76e7ddp-1, 0x1.42d6dab45c848p-1}, // exponent = 0
        {0x1.958f000000000p+1, 0x1.7800000000000p+0, 0x1.5c9882b931057p-1, 0x1.433055f7235dbp-2}, // exponent = 1
        {0x1.96406a0000000p+2, 0x1.da00000000000p+0, 0x1.1485f0e0acd3bp-1, 0x1.42a332325db6bp-3}, // exponent = 2

        /* mantissa = 0x1.98... */
        {0x1.9bfcc00000000p+0, 0x1.2c00000000000p+0, 0x1.b4e81b4e81b4fp-1, 0x1.3e254e465d72cp-1}, // exponent = 0
        {0x1.99ffaac1ec3c0p+1, 0x1.795e000000000p+0, 0x1.5b55320eae3fdp-1, 0x1.3fb056724ebb2p-2}, // exponent = 1
        {0x1.9b6a700000000p+2, 0x1.dc00000000000p+0, 0x1.135c81135c811p-1, 0x1.3e9672cf3131dp-3}, // exponent = 2

        /* mantissa = 0x1.9c... */
        {0x1.9dfc708557c00p+0, 0x1.2c7c000000000p+0, 0x1.b433cf4756912p-1, 0x1.3c9c1357411b6p-1}, // exponent = 0
        {0x1.9c10940000000p+1, 0x1.7a00000000000p+0, 0x1.5ac056b015ac0p-1, 0x1.3e15ff3643c49p-2}, // exponent = 1
        {0x1.9dfe6c1816fe0p+2, 0x1.dcfe000000000p+0, 0x1.12c9df926137bp-1, 0x1.3c9a8f2a1f8a5p-3}, // exponent = 2

        /* mantissa = 0x1.a0... */
        {0x1.a1f8756df7480p+0, 0x1.2d72000000000p+0, 0x1.b2cfd6b4a2ec0p-1, 0x1.39976b1b376fbp-1}, // exponent = 0
        {0x1.a2a3e00000000p+1, 0x1.7c00000000000p+0, 0x1.58ed2308158edp-1, 0x1.391703ea2d9b9p-2}, // exponent = 1
        {0x1.a09f9e0000000p+2, 0x1.de00000000000p+0, 0x1.12358e75d3033p-1, 0x1.3a9afad059b87p-3}, // exponent = 2

        /* mantissa = 0x1.a4... */
        {0x1.a448380000000p+0, 0x1.2e00000000000p+0, 0x1.b2036406c80d9p-1, 0x1.37dde124a87f2p-1}, // exponent = 0
        {0x1.a5fad7a3ee040p+1, 0x1.7d02000000000p+0, 0x1.580391c97b3f3p-1, 0x1.369cab16c4bb8p-2}, // exponent = 1
        {0x1.a5e0000000000p+2, 0x1.e000000000000p+0, 0x1.1111111111111p-1, 0x1.36b06e70b7421p-3}, // exponent = 2

        /* mantissa = 0x1.a8... */
        {0x1.a9fbaa05b1c00p+0, 0x1.2f5c000000000p+0, 0x1.b01182b5ac1cep-1, 0x1.33b1676d97a5bp-1}, // exponent = 0
        {0x1.a948fc0000000p+1, 0x1.7e00000000000p+0, 0x1.571ed3c506b3ap-1, 0x1.3432adb274266p-2}, // exponent = 1
        {0x1.ab2ba20000000p+2, 0x1.e200000000000p+0, 0x1.0fef010fef011p-1, 0x1.32d67431a0280p-3}, // exponent = 2

        /* mantissa = 0x1.ac... */
        {0x1.acb0000000000p+0, 0x1.3000000000000p+0, 0x1.af286bca1af28p-1, 0x1.31c079d2b089fp-1}, // exponent = 0
        {0x1.adffcaf535000p+1, 0x1.7f68000000000p+0, 0x1.55dca75792aa1p-1, 0x1.30d1b5accf7d2p-2}, // exponent = 1
        {0x1.adfb1053dbae0p+2, 0x1.e30e000000000p+0, 0x1.0f57023f898dcp-1, 0x1.30d50fe844fd2p-3}, // exponent = 2

        /* mantissa = 0x1.b0... */
        {0x1.b1ff52f400000p+0, 0x1.3140000000000p+0, 0x1.ad646ddd321c2p-1, 0x1.2e02d4701d501p-1}, // exponent = 0
        {0x1.b000000000000p+1, 0x1.8000000000000p+0, 0x1.5555555555555p-1, 0x1.2f684bda12f68p-2}, // exponent = 1
        {0x1.b082900000000p+2, 0x1.e400000000000p+0, 0x1.0ecf56be69c90p-1, 0x1.2f0cb4ca19e1ep-3}, // exponent = 2

        /* mantissa = 0x1.b4... */
        {0x1.b534480000000p+0, 0x1.3200000000000p+0, 0x1.ac5701ac5701bp-1, 0x1.2bcbbb0cb73f6p-1}, // exponent = 0
        {0x1.b6c9040000000p+1, 0x1.8200000000000p+0, 0x1.5390948f40febp-1, 0x1.2ab733230f96fp-2}, // exponent = 1
        {0x1.b5e4d60000000p+2, 0x1.e600000000000p+0, 0x1.0db20a88f4696p-1, 0x1.2b52db169e95ep-3}, // exponent = 2

        /* mantissa = 0x1.b8... */
        {0x1.b9fa0378e5c00p+0, 0x1.331c000000000p+0, 0x1.aacae5fd5e77dp-1, 0x1.288f0567537ffp-1}, // exponent = 0
        {0x1.b9fd76ec78000p+1, 0x1.82f0000000000p+0, 0x1.52bdf6a7a2620p-1, 0x1.288cb4a41a9b5p-2}, // exponent = 1
        {0x1.bb52800000000p+2, 0x1.e800000000000p+0, 0x1.0c9714fbcda3bp-1, 0x1.27a894096a4f5p-3}, // exponent = 2

        /* mantissa = 0x1.bc... */
        {0x1.bdd5400000000p+0, 0x1.3400000000000p+0, 0x1.a98ef606a63bep-1, 0x1.25fe5513ebf45p-1}, // exponent = 0
        {0x1.bda4200000000p+1, 0x1.8400000000000p+0, 0x1.51d07eae2f815p-1, 0x1.261ebd944131ep-2}, // exponent = 1
        {0x1.bdfd332712ca0p+2, 0x1.e8fa000000000p+0, 0x1.0c0dc264ce74bp-1, 0x1.25e3ff656ec87p-3}, // exponent = 2

        /* mantissa = 0x1.c0... */
        {0x1.c1fc1c0569400p+0, 0x1.34f4000000000p+0, 0x1.a83eded1251e7p-1, 0x1.2347ec39d66b0p-1}, // exponent = 0
        {0x1.c1fd3bf5cf840p+1, 0x1.8542000000000p+0, 0x1.50b90cb22a299p-1, 0x1.234731d751cccp-2}, // exponent = 1
        {0x1.c0cb9a0000000p+2, 0x1.ea00000000000p+0, 0x1.0b7e6ec259dc8p-1, 0x1.240d8e9b4ae5dp-3}, // exponent = 2

        /* mantissa = 0x1.c4... */
        {0x1.c693180000000p+0, 0x1.3600000000000p+0, 0x1.a6d01a6d01a6dp-1, 0x1.2057051321929p-1}, // exponent = 0
        {0x1.c4916c0000000p+1, 0x1.8600000000000p+0, 0x1.5015015015015p-1, 0x1.219e4a4924f1fp-2}, // exponent = 1
        {0x1.c650300000000p+2, 0x1.ec00000000000p+0, 0x1.0a6810a6810a7p-1, 0x1.20817bbcedd1fp-3}, // exponent = 2

        /* mantissa = 0x1.c8... */
        {0x1.c9fc4ad339d80p+0, 0x1.36c6000000000p+0, 0x1.a5c2b87b4e25ap-1, 0x1.1e3144d16fd97p-1}, // exponent = 0
        {0x1.cb91000000000p+1, 0x1.8800000000000p+0, 0x1.4e5e0a72f0539p-1, 0x1.1d353d43a7247p-2}, // exponent = 1
        {0x1.cbe04e0000000p+2, 0x1.ee00000000000p+0, 0x1.0953f39010954p-1, 0x1.1d040e48a75cdp-3}, // exponent = 2

        /* mantissa = 0x1.cc... */
        {0x1.cf6e000000000p+0, 0x1.3800000000000p+0, 0x1.a41a41a41a41ap-1, 0x1.1ad4948b6e145p-1}, // exponent = 0
        {0x1.cdfd181598000p+1, 0x1.88b0000000000p+0, 0x1.4dc82df5d0542p-1, 0x1.1bb66cda74540p-2}, // exponent = 1
        {0x1.cdfeef0724420p+2, 0x1.eec2000000000p+0, 0x1.08ebe9d4e24aep-1, 0x1.1bb54ba55bb8ep-3}, // exponent = 2

        /* mantissa = 0x1.d0... */
        {0x1.d1f9c6201cc80p+0, 0x1.3892000000000p+0, 0x1.a35607552f1cdp-1, 0x1.1948fa1f5ff30p-1}, // exponent = 0
        {0x1.d2a2f40000000p+1, 0x1.8a00000000000p+0, 0x1.4cab88725af6ep-1, 0x1.18e2ff3fca5acp-2}, // exponent = 1
        {0x1.d17c000000000p+2, 0x1.f000000000000p+0, 0x1.0842108421084p-1, 0x1.1994faf4aec92p-3}, // exponent = 2

        /* mantissa = 0x1.d4... */
        {0x1.d5f8615bde180p+0, 0x1.3976000000000p+0, 0x1.a22504db000b7p-1, 0x1.16e4ee12da718p-1}, // exponent = 0
        {0x1.d5f9b87878000p+1, 0x1.8af0000000000p+0, 0x1.4be15f5393e98p-1, 0x1.16e4227697dbfp-2}, // exponent = 1
        {0x1.d723520000000p+2, 0x1.f200000000000p+0, 0x1.073260a47f7c6p-1, 0x1.1633f845cb3dep-3}, // exponent = 2

        /* mantissa = 0x1.d8... */
        {0x1.d866280000000p+0, 0x1.3a00000000000p+0, 0x1.a16d3f97a4b02p-1, 0x1.1575d8c8402f4p-1}, // exponent = 0
        {0x1.d9c7600000000p+1, 0x1.8c00000000000p+0, 0x1.4afd6a052bf5bp-1, 0x1.14a6fd8916ecfp-2}, // exponent = 1
        {0x1.d9fb5ac000000p+2, 0x1.f300000000000p+0, 0x1.06ab59c7912fbp-1, 0x1.1488a6b10c148p-3}, // exponent = 2

        /* mantissa = 0x1.dc... */
        {0x1.ddfdfe805bc00p+0, 0x1.3b3c000000000p+0, 0x1.9fcacece0b241p-1, 0x1.1236b509d4023p-1}, // exponent = 0
        {0x1.ddff55aa1e600p+1, 0x1.8d2c000000000p+0, 0x1.4a036770fd266p-1, 0x1.1235f02ce295ap-2}, // exponent = 1
        {0x1.dcd6500000000p+2, 0x1.f400000000000p+0, 0x1.0624dd2f1a9fcp-1, 0x1.12e0be826d695p-3}, // exponent = 2

        /* mantissa = 0x1.e0... */
        {0x1.e17bc00000000p+0, 0x1.3c00000000000p+0, 0x1.9ec8e951033d9p-1, 0x1.1039b25a7f122p-1}, // exponent = 0
        {0x1.e0fe5c0000000p+1, 0x1.8e00000000000p+0, 0x1.49539e3b2d067p-1, 0x1.1080a9d1be542p-2}, // exponent = 1
        {0x1.e295060000000p+2, 0x1.f600000000000p+0, 0x1.05197f7d73404p-1, 0x1.0f9b07a631f92p-3}, // exponent = 2

        /* mantissa = 0x1.e4... */
        {0x1.e5ff3ecf6fc00p+0, 0x1.3cfc000000000p+0, 0x1.9d7f292cef9bap-1, 0x1.0db275be001a6p-1}, // exponent = 0
        {0x1.e5fefa40c0000p+1, 0x1.8f60000000000p+0, 0x1.48315b6c3fc79p-1, 0x1.0db29bc986108p-2}, // exponent = 1
        {0x1.e5fe06d9140e0p+2, 0x1.f72e000000000p+0, 0x1.047cca585fbe4p-1, 0x1.0db322dce8431p-3}, // exponent = 2

        /* mantissa = 0x1.e8... */
        {0x1.eaaef80000000p+0, 0x1.3e00000000000p+0, 0x1.9c2d14ee4a102p-1, 0x1.0b1f0c9a4ed7cp-1}, // exponent = 0
        {0x1.e848000000000p+1, 0x1.9000000000000p+0, 0x1.47ae147ae147bp-1, 0x1.0c6f7a0b5ed8dp-2}, // exponent = 1
        {0x1.e85f800000000p+2, 0x1.f800000000000p+0, 0x1.0410410410410p-1, 0x1.0c628f55c92dep-3}, // exponent = 2

        /* mantissa = 0x1.ec... */
        {0x1.edfb5912a5180p+0, 0x1.3eb6000000000p+0, 0x1.9b41b55ca11fcp-1, 0x1.0956733c0be03p-1}, // exponent = 0
        {0x1.efa4640000000p+1, 0x1.9200000000000p+0, 0x1.460cbc7f5cf9ap-1, 0x1.0872e8415508dp-2}, // exponent = 1
        {0x1.ee35ca0000000p+2, 0x1.fa00000000000p+0, 0x1.03091b51f5e1ap-1, 0x1.093712d33ff42p-3}, // exponent = 2

        /* mantissa = 0x1.f0... */
        {0x1.f1fd112ab0c80p+0, 0x1.3f92000000000p+0, 0x1.9a2696dd75ba1p-1, 0x1.0733ed7907e73p-1}, // exponent = 0
        {0x1.f1fc8b255bc40p+1, 0x1.92a2000000000p+0, 0x1.45898cb57730cp-1, 0x1.0734344eaebefp-2}, // exponent = 1
        {0x1.f1ff2ff2d4ba0p+2, 0x1.fb4a000000000p+0, 0x1.02609989a73cfp-1, 0x1.0732ce999c3d1p-3}, // exponent = 2

        /* mantissa = 0x1.f4... */
        {0x1.f400000000000p+0, 0x1.4000000000000p+0, 0x1.999999999999ap-1, 0x1.0624dd2f1a9fcp-1}, // exponent = 0
        {0x1.f713a00000000p+1, 0x1.9400000000000p+0, 0x1.446f86562d9fbp-1, 0x1.048a727489527p-2}, // exponent = 1
        {0x1.f417f00000000p+2, 0x1.fc00000000000p+0, 0x1.0204081020408p-1, 0x1.061850f2a7123p-3}, // exponent = 2

        /* mantissa = 0x1.f8... */
        {0x1.f9fe36d7a7d80p+0, 0x1.4146000000000p+0, 0x1.97f9f956c92fdp-1, 0x1.030a055aebeddp-1}, // exponent = 0
        {0x1.f9f8b6ce70ec0p+1, 0x1.94c6000000000p+0, 0x1.43d0d2af8e146p-1, 0x1.030cd637fd65ep-2}, // exponent = 1
        {0x1.fa05fe0000000p+2, 0x1.fe00000000000p+0, 0x1.0101010101010p-1, 0x1.03060a0f151c2p-3}, // exponent = 2

        /* mantissa = 0x1.fc... */
        {0x1.fd6f080000000p+0, 0x1.4200000000000p+0, 0x1.970e4f80cb872p-1, 0x1.014a239d8b1a9p-1}, // exponent = 0
        {0x1.fe95cc0000000p+1, 0x1.9600000000000p+0, 0x1.42d6625d51f87p-1, 0x1.00b59a78a8ffcp-2}, // exponent = 1
        {0x1.0000000000000p+3, 0x1.0000000000000p+1, 0x1.0000000000000p-1, 0x1.0000000000000p-3}, // exponent = 2
};

union floatdata { float f; int32_t x; };

float cbrtf(float x) {
        union floatdata xabs, result;
        int32_t mantissa_key;
        double r;
        const struct cbrt_table_entry *table;

        if (x != x) return x + x;

        /* Reset the sign bit to get the absolute value */
        xabs.f = (float)((int32_t)x & 0x7fffffff);
        if (xabs.f == __builtin_inff()) return (x);

        if (xabs.f < 0x1.0p-126f) { // denormal path
                if (xabs.f == 0.0f) return x;
                xabs.f *= 0x1.0p45f;

                result.x = ((xabs.x & 0x7f800000U) >> 23) - 1;
                mantissa_key = ((xabs.x & 0x007e0000U) >> 17) * 3;

                table = cbrt_table + mantissa_key + result.x%3;

                xabs.x = (xabs.x & 0x007fffffU) | ((result.x%3 + 127) << 23);
                r = ((double)xabs.f - table->x)*(table->recip_x);
                result.x = (result.x / 3 + 70) << 23;
                result.x = (result.x & 0x7fffffff)
                        | (*(int32_t *) &x & 0x80000000);
        } else {
                result.x = ((xabs.x & 0x7f800000U) >> 23) - 1;
                mantissa_key = ((xabs.x & 0x007e0000U) >> 17) * 3;

                table = cbrt_table + mantissa_key + result.x%3;

                xabs.x = (xabs.x & 0x007fffffU) | ((result.x%3 + 127) << 23);
                r = ((double)xabs.f - table->x)*(table->recip_x);
                result.x = (result.x / 3 + 85) << 23;
                result.x = (result.x & 0x7fffffff)
                        | (*(int32_t *) &x & 0x80000000);
        }

        /* Bigger polynomial for correctly rounded cbrt. */
        double poly = 1.0 + (.333333333333341976693463092094589 + (-.111111111111154331658603135046499 + (0.617283944244925372967204212785709e-1 + (-0.411522622533364699898800342654033e-1 + (0.301852863186459692668300411679515e-1 - 0.234797653033909108182788624401527e-1*r)*r)*r)*r)*r)*r;

        poly *= table->cbrt_x;
        result.f *= (float)poly;
        return(result.f);
}
