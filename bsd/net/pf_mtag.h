/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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

#ifndef _NET_PF_MTAG_H_
#define _NET_PF_MTAG_H_

#if PF
#if KERNEL_PRIVATE

#ifdef  __cplusplus
extern "C" {
#endif

#define	PF_TAG_GENERATED		0x01
#define	PF_TAG_FRAGCACHE		0x02
#define	PF_TAG_TRANSLATE_LOCALHOST	0x04

struct pf_mtag {
	void		*hdr;		/* saved hdr pos in mbuf, for ECN */
	unsigned int	rtableid;	/* alternate routing table id */
	u_int32_t	qid;		/* queue id */
	u_int16_t	tag;		/* tag id */
	u_int8_t	flags;
	u_int8_t	routed;
};

__private_extern__ struct pf_mtag *pf_find_mtag(struct mbuf *);
__private_extern__ struct pf_mtag *pf_get_mtag(struct mbuf *);

#ifdef  __cplusplus
}
#endif
#endif /* KERNEL_PRIVATE */
#endif /* PF */
#endif /* _NET_PF_MTAG_H_ */
