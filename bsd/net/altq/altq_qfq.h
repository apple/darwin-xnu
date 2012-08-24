/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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

#ifndef _NET_ALTQ_ALTQ_QFQ_H_
#define	_NET_ALTQ_ALTQ_QFQ_H_

#include <net/pfvar.h>
#include <net/altq/altq.h>
#include <net/pktsched/pktsched_qfq.h>

#ifdef BSD_KERNEL_PRIVATE
#ifdef __cplusplus
extern "C" {
#endif

extern int	altq_qfq_pfattach(struct pf_altq *);
extern int	altq_qfq_add(struct pf_altq *);
extern int	altq_qfq_remove(struct pf_altq *);
extern int	altq_qfq_add_queue(struct pf_altq *);
extern int	altq_qfq_remove_queue(struct pf_altq *);
extern int	altq_qfq_getqstats(struct pf_altq *, void *, int *);

#ifdef __cplusplus
}
#endif
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _NET_ALTQ_ALTQ_QFQ_H_ */
