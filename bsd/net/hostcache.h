/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright 1997 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _NET_HOSTCACHE_H
#define	_NET_HOSTCACHE_H	1

/*
 * This file defines the interface between network protocols and
 * the cache of host-specific information maintained by the kernel.
 * The generic interface takes care of inserting and deleting entries,
 * maintaining mutual exclusion, and enforcing policy constraint on the
 * size of the cache and the maximum age of its entries.
 * It replaces an earlier scheme which overloaded the routing table
 * for this purpose, and should be significantly more efficient
 * at performing most operations.  (It does keep a route to each
 * entry in the cache.)  Most protocols will want to define a
 * structure which begins with `struct hcentry' so that they
 * can keep additional, protocol-specific information in it.
 */

#include <sys/queue.h>

struct hcentry {
	LIST_ENTRY(hcentry) hc_link;
	struct	timeval hc_idlesince;	/* time last ref dropped */
	struct	sockaddr *hc_host;	/* address of this entry's host */
	struct	rtentry *hc_rt;		/* route to get there */
	/* struct nexthop *hc_nh; */
	int	hc_refcnt;		/* reference count */
	struct	hctable *hc_hct; 	/* back ref to table */
};

struct hccallback {
	u_long	(*hccb_hash)(struct sockaddr *, u_long);
	int	(*hccb_delete)(struct hcentry *);
	u_long	(*hccb_bump)(u_long);
};

LIST_HEAD(hchead, hcentry);

struct hctable {
	u_long	hct_nentries;
	u_long	hct_active;
	u_long	hct_idle;
	struct	hchead *hct_heads;
	struct	hccallback *hct_cb;
	int	hct_primes;
};

#ifdef KERNEL

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_HOSTCACHE);
#endif
/*
 * The table-modification functions must be called from user mode, as
 * they may block waiting for memory and/or locks.
 */
int	hc_init(int af, struct hccallback *hccb, int init_nelem, int primes);
struct	hcentry *hc_get(struct sockaddr *sa);
void	hc_ref(struct hcentry *hc);
void	hc_rele(struct hcentry *hc);
int	hc_insert(struct hcentry *hc);
int	hc_delete(struct hcentry *hc);
#endif /* KERNEL */

#endif /* _NET_HOSTCACHE_H */
