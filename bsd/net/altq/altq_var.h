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

/*	$NetBSD: altq_var.h,v 1.10 2006/10/15 13:17:13 peter Exp $	*/
/*	$KAME: altq_var.h,v 1.18 2005/04/13 03:44:25 suz Exp $	*/

/*
 * Copyright (C) 1998-2003
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _NET_ALTQ_ALTQ_VAR_H_
#define	_NET_ALTQ_ALTQ_VAR_H_

#ifdef BSD_KERNEL_PRIVATE
#if PF_ALTQ
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#include <net/pktsched/pktsched.h>
#include <net/classq/classq.h>
#include <net/altq/if_altq.h>
#if PKTSCHED_HFSC
#include <net/altq/altq_hfsc.h>
#endif /* PKTSCHED_HFSC */
#if PKTSCHED_FAIRQ
#include <net/altq/altq_fairq.h>
#endif /* PKTSCHED_FAIRQ */
#if PKTSCHED_CBQ
#include <net/altq/altq_cbq.h>
#endif /* PKTSCHED_CBQ */
#if PKTSCHED_PRIQ
#include <net/altq/altq_priq.h>
#endif /* PKTSCHED_PRIQ */
#include <net/altq/altq_qfq.h>

struct pf_altq;

extern void	*altq_lookup(char *, u_int32_t);
extern int	altq_pfattach(struct pf_altq *);
extern int	altq_pfdetach(struct pf_altq *);
extern int	altq_add(struct pf_altq *);
extern int	altq_remove(struct pf_altq *);
extern int	altq_add_queue(struct pf_altq *);
extern int	altq_remove_queue(struct pf_altq *);
extern int	altq_getqstats(struct pf_altq *, void *, int *);

#endif /* PF_ALTQ */
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _NET_ALTQ_ALTQ_VAR_H_ */
