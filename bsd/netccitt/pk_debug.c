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
 * Copyright (c) University of British Columbia, 1984
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Laboratory for Computation Vision and the Computer Science Department
 * of the University of British Columbia.
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
 *	@(#)pk_debug.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/malloc.h>

#include <net/if.h>

#include <netccitt/x25.h>
#include <netccitt/pk.h>
#include <netccitt/pk_var.h>

char	*pk_state[] = {
	"Listen",	"Ready",	"Received-Call",
	"Sent-Call",	"Data-Transfer","Received-Clear",
	"Sent-Clear",
};

char   *pk_name[] = {
	"Call",		"Call-Conf",	"Clear",
	"Clear-Conf",	"Data",		"Intr",		"Intr-Conf",
	"Rr",		"Rnr",		"Reset",	"Reset-Conf",
	"Restart",	"Restart-Conf",	"Reject",	"Diagnostic",
	"Invalid"
};

pk_trace (xcp, m, dir)
struct x25config *xcp;
register struct mbuf *m;
char *dir;
{
	register char *s;
	struct x25_packet *xp = mtod(m, struct x25_packet *);
	register int i, len = 0, cnt = 0;

	if (xcp -> xc_ptrace == 0)
		return;

	i = pk_decode (xp) / MAXSTATES;
	for (; m; m = m -> m_next) {
		len = len + m -> m_len;
		++cnt;
	}
	printf ("LCN=%d %s:	%s	#=%d, len=%d ",
		LCN(xp), dir, pk_name[i], cnt, len);
	for (s = (char *) xp, i = 0; i < 5; ++i, ++s)
		printf ("%x ", (int) * s & 0xff);
	printf ("\n");
}

mbuf_cache(c, m)
register struct mbuf_cache *c;
struct mbuf *m;
{
	register struct mbuf **mp;

	if (c->mbc_size != c->mbc_oldsize) {
		unsigned zero_size, copy_size;
		unsigned new_size = c->mbc_size * sizeof(m);
		caddr_t cache = (caddr_t)c->mbc_cache;

		if (new_size) {
//			c->mbc_cache = (struct mbuf **)
//				malloc(new_size, M_MBUF, M_NOWAIT);
			MALLOC(c->mbc_cache, struct mbuf **, new_size, M_MBUF, M_NOWAIT);
			if (c->mbc_cache == 0) {
				c->mbc_cache = (struct mbuf **)cache;
				return;
			}
			c->mbc_num %= c->mbc_size;
		} else
			c->mbc_cache = 0;
		if (c->mbc_size < c->mbc_oldsize) {
			register struct mbuf **mplim;
			mp = c->mbc_size + (struct mbuf **)cache;
			mplim = c->mbc_oldsize + (struct mbuf **)cache;
			while (mp < mplim)
				m_freem(*mp++);
			zero_size = 0;
		} else
			zero_size = (c->mbc_size - c->mbc_oldsize) * sizeof(m);
		copy_size = new_size - zero_size;
		c->mbc_oldsize = c->mbc_size;
		if (copy_size)
			bcopy(cache, (caddr_t)c->mbc_cache, copy_size);
		if (cache)
			FREE(cache, M_MBUF);
		if (zero_size)
			bzero(copy_size + (caddr_t)c->mbc_cache, zero_size);
	}
	if (c->mbc_size == 0)
		return;
	mp = c->mbc_cache + c->mbc_num;
	c->mbc_num = (1 + c->mbc_num) % c->mbc_size;
	if (*mp)
		m_freem(*mp);
	if (*mp = m_copym(m, 0, M_COPYALL, M_DONTWAIT))
		(*mp)->m_flags |= m->m_flags & 0x08;
}
