/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
// #include <Availability.h>
#include <sys/cdefs.h>

#if defined(__clang__) && ((defined(__apple_build_version__) && __apple_build_version__ > 5010000))
#define __USES_V_CRYPTO_INTRINSICS 1
#else
#define __USES_V_CRYPTO_INTRINSICS 0
#endif


//  AES INSTRUCTIONS
// aese.16b	v0, v1
// aesd.16b	v0, v1
// aesmc.16b	v0, v1
// aesimc.16b	v0, v1

// SHA1 INTRINSICS
// sha1su0.4s	v0, v1, v2
// sha1su1.4s	v0, v1
// sha1c.4s	v0, v1, v2		// or q0, s1, v2.4s
// sha1m.4s	v0, v1, v2		// or q0, s1, v2.4s
// sha1p.4s	v0, v1, v2		// or q0, s1, v2.4s
// sha1h.4s	v0, v1		// or s0, s1

// SHA256 INTRINSICS
// sha256su0.4s	v0, v1
// sha256su1.4s	v0, v1, v2
// sha256h.4s		v0, v1, v2		// or q0, q1, v2.4s
// sha256h2.4s	v0, v1, v2		// or q0, q1, v2.4s


#if __USES_V_CRYPTO_INTRINSICS == 1
.macro  AESE
aese.16b v$0, v$1
.endm

.macro  AESD
aesd.16b v$0, v$1
.endm

.macro  AESMC
aesmc.16b v$0, v$1
.endm

.macro  AESIMC
aesimc.16b v$0, v$1
.endm


#else

.macro  AESE
aese q$0, q$1
.endm

.macro  AESD
aesd q$0, q$1
.endm

.macro  AESMC
aesmc q$0, q$1
.endm

.macro  AESIMC
aesimc q$0, q$1
.endm

#endif

#if __USES_V_CRYPTO_INTRINSICS == 1

.macro SHA1SU0
sha1su0 v$0.4s, v$1.4s, v$2.4s
.endm

.macro SHA1SU1
sha1su1 v$0.4s, v$1.4s
.endm

.macro SHA1C
sha1c   q$0, s$1, v$2.4s
.endm

.macro SHA1M
sha1m   q$0, s$1, v$2.4s
.endm

.macro SHA1P
sha1p   q$0, s$1, v$2.4s
.endm

.macro SHA1H
sha1h   s$0, s$1
.endm

.macro SHA256SU0
sha256su0    v$0.4s, v$1.4s
.endm

.macro SHA256SU1
sha256su1    v$0.4s, v$1.4s, v$2.4s
.endm

.macro SHA256H
sha256h    q$0, q$1, v$2.4s
.endm

.macro SHA256H2
sha256h2    q$0, q$1, v$2.4s
.endm

#else

.macro SHA1SU0
sha1su0 q$0, q$1, q$2
.endm

.macro SHA1SU1
sha1su1 q$0, q$1
.endm

.macro SHA1C
sha1c   q$0, q$1, q$2
.endm

.macro SHA1M
sha1m   q$0, q$1, q$2
.endm

.macro SHA1P
sha1p   q$0, q$1, q$2
.endm

.macro SHA1H
sha1h   q$0, q$1
.endm

.macro SHA256SU0
sha256su0    q$0, q$1
.endm

.macro SHA256SU1
sha256su1    q$0, q$1, q$2
.endm

.macro SHA256H
sha256h    q$0, q$1, q$2
.endm

.macro SHA256H2
sha256h2    q$0, q$1, q$2
.endm

#endif
