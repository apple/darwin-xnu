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
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tuba_table.c	8.2 (Berkeley) 11/15/93
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/radix.h>

#include <netiso/iso.h>
#include <netiso/tuba_table.h>

int	tuba_table_size;
struct	tuba_cache **tuba_table;
struct	radix_node_head *tuba_tree;
extern	int arpt_keep, arpt_prune;	/* use same values as arp cache */

void
tuba_timer()
{
	int s = splnet();
	int	i;
	register struct	tuba_cache *tc;
	long	timelimit = time.tv_sec - arpt_keep;

	timeout(tuba_timer, (caddr_t)0, arpt_prune * hz);
	for (i = tuba_table_size; i > 0; i--)
		if ((tc = tuba_table[i]) && (tc->tc_refcnt == 0) &&
		    (tc->tc_time < timelimit)) {
			tuba_table[i] = 0;
			rn_delete(&tc->tc_siso.siso_addr, NULL, tuba_tree);
			FREE((caddr_t)tc, M_RTABLE);
		}
	splx(s);
}

tuba_table_init()
{
	rn_inithead((void **)&tuba_tree, 40);
	timeout(tuba_timer, (caddr_t)0, arpt_prune * hz);
}

int
tuba_lookup(siso, wait)
	register struct sockaddr_iso *siso;
{
	struct radix_node *rn, *rn_match();
	register struct tuba_cache *tc;
	struct tuba_cache **new;
	int dupentry = 0, sum_a = 0, sum_b = 0, old_size, i;

	if ((rn = rn_match((caddr_t)&siso->siso_addr, tuba_tree->rnh_treetop))
	     && ((rn->rn_flags & RNF_ROOT) == 0)) {
		tc = (struct tuba_cache *)rn;
		tc->tc_time = time.tv_sec;
		return (tc->tc_index);
	}
//	if ((tc = (struct tuba_cache *)malloc(sizeof(*tc), M_RTABLE, wait))
//		== NULL)
	if (wait == M_DONTWAIT)
		MALLOC(tc, struct tuba_cache *, sizeof(*tc), M_RTABLE, M_NOWAIT);
	else
		MALLOC(tc, struct tuba_cache *, sizeof(*tc), M_RTABLE, M_WAITOK);
	if (tc == NULL)
		return (0);
	bzero((caddr_t)tc, sizeof (*tc));
	bcopy(siso->siso_data, tc->tc_siso.siso_data,
		tc->tc_siso.siso_nlen =  siso->siso_nlen);
	rn_insert(&tc->tc_siso.siso_addr, tuba_tree, &dupentry, tc->tc_nodes);
	if (dupentry)
		panic("tuba_lookup 1");
	tc->tc_siso.siso_family = AF_ISO;
	tc->tc_siso.siso_len = sizeof(tc->tc_siso);
	tc->tc_time = time.tv_sec;
	for (i = sum_a = tc->tc_siso.siso_nlen; --i >= 0; )
		(i & 1 ? sum_a : sum_b) += (u_char)tc->tc_siso.siso_data[i];
	REDUCE(tc->tc_sum, (sum_a << 8) + sum_b);
	HTONS(tc->tc_sum);
	SWAB(tc->tc_ssum, tc->tc_sum);
	for (i = tuba_table_size; i > 0; i--)
		if (tuba_table[i] == 0)
			goto fixup;
	old_size = tuba_table_size;
	if (tuba_table_size == 0)
		tuba_table_size = 15;
	if (tuba_table_size > 0x7fff)
		return (0);
	tuba_table_size = 1 + 2 * tuba_table_size;
	i = (tuba_table_size + 1) * sizeof(tc);
//	new = (struct tuba_cache **)malloc((unsigned)i, M_RTABLE, wait);
	if (wait == M_DONTWAIT)
		MALLOC(new, struct tuba_cache **, i, M_RTABLE, M_NOWAIT);
	else
		MALLOC(new, struct tuba_cache **, i, M_RTABLE, M_WAITOK);
	if (new == 0) {
		tuba_table_size = old_size;
		rn_delete(&tc->tc_siso.siso_addr, NULL, tuba_tree);
		FREE((caddr_t)tc, M_RTABLE);
		return (0);
	}
	bzero((caddr_t)new, (unsigned)i);
	if (tuba_table) {
		bcopy((caddr_t)tuba_table, (caddr_t)new, i >> 1);
		FREE((caddr_t)tuba_table, M_RTABLE);
	}
	tuba_table = new;
	i = tuba_table_size;
fixup:
	tuba_table[i] = tc;
	tc->tc_index = i;
	return (tc->tc_index);
}
