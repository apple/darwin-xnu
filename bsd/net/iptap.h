/*
 * Copyright (c) 1999-2010 Apple Inc. All rights reserved.
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
#ifndef IPTAP_H
#define IPTAP_H

#include <net/if.h>

#define IPTAP_CONTROL_NAME "com.apple.net.iptap_control"

#define IPTAP_BUFFERSZ	(128 * 1024)
#define IPTAP_VERSION_1		0x1

enum {
	IPTAP_OUTPUT_TAG	=	0x01,
	IPTAP_INPUT_TAG		=	0x10,
	IPTAP_UNKNOWN_TAG	=	0x11
};

#pragma pack(push)
#pragma pack(1)

typedef struct iptap_hdr_t {
	uint32_t	hdr_length;
	uint8_t		version;
	uint32_t	length;
	uint8_t		type;
	uint16_t	unit;
	uint8_t		io;
	uint32_t	protocol_family;
	uint32_t	frame_pre_length;
	uint32_t	frame_pst_length;
	char		if_name[IFNAMSIZ];
} __attribute__ ((__packed__)) iptap_hdr_t;

#pragma pack(pop)

#ifdef KERNEL_PRIVATE

extern void iptap_init(void);
extern void iptap_ipf_input(struct ifnet *, protocol_family_t, struct mbuf *, char *);
extern void iptap_ipf_output(struct ifnet *, protocol_family_t, struct mbuf *, u_int32_t, u_int32_t);
#if 0
extern void iptap_destroy(void);
#endif

#endif /* KERNEL_PRIVATE */
#endif /* IPTAP_H */