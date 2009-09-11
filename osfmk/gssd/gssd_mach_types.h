/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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

#ifndef _GSSD_MACH_TYPES_H_
#define _GSSD_MACH_TYPES_H_

typedef enum mechtype { DEFAULT_MECH = 0, KRB5_MECH = 0, SPNEGO_MECH } mechtype;
typedef char *string_t;
typedef uint8_t *byte_buffer;
typedef uint32_t *gid_list;
typedef uint64_t gss_ctx;
typedef uint64_t gss_cred;

#define GSSD_GSS_FLAGS_MASK	0x1FF
/* The following need to correspond to GSS_C_*_FLAG in gssapi.h */
#define GSSD_DELEG_FLAG		1
#define GSSD_MUTUAL_FLAG		2
#define GSSD_REPLAY_FLAG		4
#define GSSD_SEQUENCE_FLAG	8
#define GSSD_CONF_FLAG		16
#define GSSD_INTEG_FLAG		32
#define GSSD_ANON_FLAG		64
#define GSSD_PROT_FLAG		128
#define GSSD_TRANS_FLAG		256
#define GSSD_C_DELEG_POLICY_FLAG 32768

#define GSSD_FLAGS_SHIFT		0
#define GSSD_NO_DEFAULT		(1 << GSSD_FLAGS_SHIFT) // Only use principal from uid
#define GSSD_NO_CANON		(2 << GSSD_FLAGS_SHIFT) // Don't canononicalize host names
#define GSSD_HOME_ACCESS_OK	(4 << GSSD_FLAGS_SHIFT) // OK to access home directory
#define GSSD_UI_OK		(8 << GSSD_FLAGS_SHIFT) // OK to bring up UI
#define GSSD_RESTART		(16 << GSSD_FLAGS_SHIFT) // Destroy the supplied context and start over
#define GSSD_NFS_1DES		(64 << GSSD_FLAGS_SHIFT) // Only get single DES session keys
#define GSSD_WIN2K_HACK		(128 << GSSD_FLAGS_SHIFT) // Hack for Win2K


#endif /* _GSSD_MACH_TYPES_H_ */
