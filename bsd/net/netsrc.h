/*
 * Copyright (c) 2011-2013 Apple Inc. All rights reserved.
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

#ifndef __NET_NETSRC_H__

#define	NETSRC_CTLNAME	"com.apple.netsrc"

#define	NETSRC_VERSION1	1
#define	NETSRC_CURVERS	NETSRC_VERSION1

struct netsrc_req {
	unsigned int nrq_ver;
	unsigned int nrq_ifscope;
	union {
		struct sockaddr_in  _usin;
		struct sockaddr_in6 _usin6;
	} _usa;
};

#define	nrq_sin		_usa._usin
#define	nrq_sin6	_usa._usin6

struct netsrc_rep {
	union {
		struct sockaddr_in  _usin;
		struct sockaddr_in6 _usin6;
	} _usa;
#define	NETSRC_IP6_FLAG_TENTATIVE	0x0001
#define	NETSRC_IP6_FLAG_TEMPORARY	0x0002
#define	NETSRC_IP6_FLAG_DEPRECATED	0x0004
#define	NETSRC_IP6_FLAG_OPTIMISTIC	0x0008
#define	NETSRC_IP6_FLAG_SECURED		0x0010
	uint16_t nrp_flags;
	uint16_t nrp_label;
	uint16_t nrp_precedence;
	uint16_t nrp_dstlabel;
	uint16_t nrp_dstprecedence;
};

#define	nrp_sin		_usa._usin
#define	nrp_sin6	_usa._usin6

#ifdef KERNEL_PRIVATE
__private_extern__ void netsrc_init(void);
#endif

#endif /* __NET_NETSRC_H__ */
