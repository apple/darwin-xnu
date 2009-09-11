/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
/*	$NetBSD: uipc_mbuf.c,v 1.40 1999/04/01 00:23:25 thorpej Exp $	*/

/*
 * Copyright (C) 1999 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1982, 1986, 1988, 1991, 1993
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
 *	@(#)uipc_mbuf.c	8.4 (Berkeley) 2/14/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */


/*#define PULLDOWN_DEBUG*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#if defined(PULLDOWN_STAT) && defined(INET6)
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

/*
 * ensure that [off, off + len) is contiguous on the mbuf chain "m".
 * packet chain before "off" is kept untouched.
 * if offp == NULL, the target will start at <retval, 0> on resulting chain.
 * if offp != NULL, the target will start at <retval, *offp> on resulting chain.
 *
 * on error return (NULL return value), original "m" will be freed.
 *
 * XXX M_TRAILINGSPACE/M_LEADINGSPACE on shared cluster (sharedcluster)
 */
struct mbuf *
m_pulldown(struct mbuf *m, int off, int len, int *offp)
{
	struct mbuf *n, *o;
	int hlen, tlen, olen;
	int sharedcluster;
#if defined(PULLDOWN_STAT) && defined(INET6)
	static struct mbuf *prev = NULL;
	int prevlen = 0, prevmlen = 0;
#endif

	/* check invalid arguments. */
	if (m == NULL)
		panic("m == NULL in m_pulldown()");
	if (len > MCLBYTES) {
		m_freem(m);
		return NULL;	/* impossible */
	}

#if defined(PULLDOWN_STAT) && defined(INET6)
	ip6stat.ip6s_pulldown++;
#endif

#if defined(PULLDOWN_STAT) && defined(INET6)
	/* statistics for m_pullup */
	ip6stat.ip6s_pullup++;
	if (off + len > MHLEN)
		ip6stat.ip6s_pullup_fail++;
	else {
		int dlen, mlen;

		dlen = (prev == m) ? prevlen : m->m_len;
		mlen = (prev == m) ? prevmlen : m->m_len + M_TRAILINGSPACE(m);

		if (dlen >= off + len)
			ip6stat.ip6s_pullup--; /* call will not be made! */
		else if ((m->m_flags & M_EXT) != 0) {
			ip6stat.ip6s_pullup_alloc++;
			ip6stat.ip6s_pullup_copy++;
		} else {
			if (mlen >= off + len)
				ip6stat.ip6s_pullup_copy++;
			else {
				ip6stat.ip6s_pullup_alloc++;
				ip6stat.ip6s_pullup_copy++;
			}
		}

		prevlen = off + len;
		prevmlen = MHLEN;
	}

	/* statistics for m_pullup2 */
	ip6stat.ip6s_pullup2++;
	if (off + len > MCLBYTES)
		ip6stat.ip6s_pullup2_fail++;
	else {
		int dlen, mlen;

		dlen = (prev == m) ? prevlen : m->m_len;
		mlen = (prev == m) ? prevmlen : m->m_len + M_TRAILINGSPACE(m);
		prevlen = off + len;
		prevmlen = mlen;

		if (dlen >= off + len)
			ip6stat.ip6s_pullup2--; /* call will not be made! */
		else if ((m->m_flags & M_EXT) != 0) {
			ip6stat.ip6s_pullup2_alloc++;
			ip6stat.ip6s_pullup2_copy++;
			prevmlen = (off + len > MHLEN) ? MCLBYTES : MHLEN;
		} else {
			if (mlen >= off + len)
				ip6stat.ip6s_pullup2_copy++;
			else {
				ip6stat.ip6s_pullup2_alloc++;
				ip6stat.ip6s_pullup2_copy++;
				prevmlen = (off + len > MHLEN) ? MCLBYTES
							       : MHLEN;
			}
		}
	}

	prev = m;
#endif

#ifdef PULLDOWN_DEBUG
    {
	struct mbuf *t;
	printf("before:");
	for (t = m; t; t = t->m_next)
		printf(" %d", t->m_len);
	printf("\n");
    }
#endif
	n = m;
	while (n != NULL && off > 0) {
		if (n->m_len > off)
			break;
		off -= n->m_len;
		n = n->m_next;
	}
	/* be sure to point non-empty mbuf */
	while (n != NULL && n->m_len == 0)
		n = n->m_next;
	if (!n) {
		m_freem(m);
		return NULL;	/* mbuf chain too short */
	}

	/*
	 * the target data is on <n, off>.
	 * if we got enough data on the mbuf "n", we're done.
	 */
	if ((off == 0 || offp) && len <= n->m_len - off)
		goto ok;

#if defined(PULLDOWN_STAT) && defined(INET6)
	ip6stat.ip6s_pulldown_copy++;
#endif

	/*
	 * when len < n->m_len - off and off != 0, it is a special case.
	 * len bytes from <n, off> sits in single mbuf, but the caller does
	 * not like the starting position (off).
	 * chop the current mbuf into two pieces, set off to 0.
	 */
	if (len < n->m_len - off) {
		o = m_copym(n, off, n->m_len - off, M_DONTWAIT);
		if (o == NULL) {
			m_freem(m);
			return NULL;	/* ENOBUFS */
		}
		n->m_len = off;
		o->m_next = n->m_next;
		n->m_next = o;
		n = n->m_next;
		off = 0;
		goto ok;
	}

	/*
	 * we need to take hlen from <n, off> and tlen from <n->m_next, 0>,
	 * and construct contiguous mbuf with m_len == len.
	 * note that hlen + tlen == len, and tlen > 0.
	 */
	hlen = n->m_len - off;
	tlen = len - hlen;

	/*
	 * ensure that we have enough trailing data on mbuf chain.
	 * if not, we can do nothing about the chain.
	 */
	olen = 0;
	for (o = n->m_next; o != NULL; o = o->m_next)
		olen += o->m_len;
	if (hlen + olen < len) {
		m_freem(m);
		return NULL;	/* mbuf chain too short */
	}

	/*
	 * easy cases first.
	 * we need to use m_copydata() to get data from <n->m_next, 0>.
	 */
	if ((n->m_flags & M_EXT) == 0)
		sharedcluster = 0;
	else {
		if (n->m_ext.ext_free)
			sharedcluster = 1;
		else if (m_mclhasreference(n))
			sharedcluster = 1;
		else
			sharedcluster = 0;
	}
	if ((off == 0 || offp) && M_TRAILINGSPACE(n) >= tlen
	 && !sharedcluster) {
		m_copydata(n->m_next, 0, tlen, mtod(n, caddr_t) + n->m_len);
		n->m_len += tlen;
		m_adj(n->m_next, tlen);
		goto ok;
	}
	if ((off == 0 || offp) && M_LEADINGSPACE(n->m_next) >= hlen
	 && !sharedcluster) {
		n->m_next->m_data -= hlen;
		n->m_next->m_len += hlen;
		bcopy(mtod(n, caddr_t) + off, mtod(n->m_next, caddr_t), hlen);
		n->m_len -= hlen;
		n = n->m_next;
		off = 0;
		goto ok;
	}

	/*
	 * now, we need to do the hard way.  don't m_copy as there's no room
	 * on both end.
	 */
#if defined(PULLDOWN_STAT) && defined(INET6)
	ip6stat.ip6s_pulldown_alloc++;
#endif
	MGET(o, M_DONTWAIT, m->m_type);
	if (o == NULL) {
		m_freem(m);
		return NULL;	/* ENOBUFS */
	}
	if (len > MHLEN) {	/* use MHLEN just for safety */
		MCLGET(o, M_DONTWAIT);
		if ((o->m_flags & M_EXT) == 0) {
			m_freem(m);
			m_free(o);
			return NULL;	/* ENOBUFS */
		}
	}
	/* get hlen from <n, off> into <o, 0> */
	o->m_len = hlen;
	bcopy(mtod(n, caddr_t) + off, mtod(o, caddr_t), hlen);
	n->m_len -= hlen;
	/* get tlen from <n->m_next, 0> into <o, hlen> */
	m_copydata(n->m_next, 0, tlen, mtod(o, caddr_t) + o->m_len);
	o->m_len += tlen;
	m_adj(n->m_next, tlen);
	o->m_next = n->m_next;
	n->m_next = o;
	n = o;
	off = 0;

ok:
#ifdef PULLDOWN_DEBUG
    {
	struct mbuf *t;
	printf("after:");
	for (t = m; t; t = t->m_next)
		printf("%c%d", t == n ? '*' : ' ', t->m_len);
	printf(" (off=%d)\n", off);
    }
#endif
	if (offp)
		*offp = off;
	return n;
}

/* Get a packet tag structure along with specified data following. */
struct m_tag *
m_tag_alloc(u_int32_t id, u_int16_t type, int len, int wait)
{
	struct m_tag *t;

	if (len < 0)
		return NULL;
#if CONFIG_MBUF_TAGS_MALLOC
	t = _MALLOC(len + sizeof (struct m_tag), M_TEMP, wait);
#else
        if (len + sizeof(struct m_tag) <= MLEN) {
		struct mbuf *m = m_get(wait, MT_TAG);
		if (m == NULL)
			return NULL;
		t = mtod(m, struct m_tag *);
        } else if (len + sizeof(struct m_tag) <= MCLBYTES) {
        	t = (struct m_tag *) m_mclalloc(wait);
        } else
                t = NULL;
#endif
	if (t == NULL)
		return NULL;
	t->m_tag_type = type;
	t->m_tag_len = len;
	t->m_tag_id = id;
	return t;
}


/* Free a packet tag. */
void
m_tag_free(struct m_tag *t)
{
#if CONFIG_MACF_NET
	if (t != NULL && 
	    t->m_tag_id   == KERNEL_MODULE_TAG_ID &&
	    t->m_tag_type == KERNEL_TAG_TYPE_MACLABEL)
		mac_mbuf_tag_destroy(t);
#endif
#if CONFIG_MBUF_TAGS_MALLOC
	_FREE(t, M_TEMP);
#else
	if (t == NULL)
		return;
	if (t->m_tag_len + sizeof(struct m_tag) <= MLEN) {
		struct mbuf * m = m_dtom(t);
		m_free(m);
	} else {
		MCLFREE((caddr_t)t);
	}
#endif
}

/* Prepend a packet tag. */
void
m_tag_prepend(struct mbuf *m, struct m_tag *t)
{
	KASSERT(m && t, ("m_tag_prepend: null argument, m %p t %p", m, t));
	SLIST_INSERT_HEAD(&m->m_pkthdr.tags, t, m_tag_link);
}

/* Unlink a packet tag. */
void
m_tag_unlink(struct mbuf *m, struct m_tag *t)
{
	KASSERT(m && t, ("m_tag_unlink: null argument, m %p t %p", m, t));
	SLIST_REMOVE(&m->m_pkthdr.tags, t, m_tag, m_tag_link);
}

/* Unlink and free a packet tag. */
void
m_tag_delete(struct mbuf *m, struct m_tag *t)
{
	KASSERT(m && t, ("m_tag_delete: null argument, m %p t %p", m, t));
	m_tag_unlink(m, t);
	m_tag_free(t);
}

/* Unlink and free a packet tag chain, starting from given tag. */
void
m_tag_delete_chain(struct mbuf *m, struct m_tag *t)
{
	struct m_tag *p, *q;

	KASSERT(m, ("m_tag_delete_chain: null mbuf"));
	if (t != NULL)
		p = t;
	else
		p = SLIST_FIRST(&m->m_pkthdr.tags);
	if (p == NULL)
		return;
	while ((q = SLIST_NEXT(p, m_tag_link)) != NULL)
		m_tag_delete(m, q);
	m_tag_delete(m, p);
}

/* Find a tag, starting from a given position. */
struct m_tag *
m_tag_locate(struct mbuf *m, u_int32_t id, u_int16_t type, struct m_tag *t)
{
	struct m_tag *p;

	KASSERT(m, ("m_tag_find: null mbuf"));
	if (t == NULL)
		p = SLIST_FIRST(&m->m_pkthdr.tags);
	else
		p = SLIST_NEXT(t, m_tag_link);
	while (p != NULL) {
		if (p->m_tag_id == id && p->m_tag_type == type)
			return p;
		p = SLIST_NEXT(p, m_tag_link);
	}
	return NULL;
}

/* Copy a single tag. */
struct m_tag *
m_tag_copy(struct m_tag *t, int how)
{
	struct m_tag *p;

	KASSERT(t, ("m_tag_copy: null tag"));
	p = m_tag_alloc(t->m_tag_id, t->m_tag_type, t->m_tag_len, how);
	if (p == NULL)
		return (NULL);
#if CONFIG_MACF_NET
	/*
	 * XXXMAC: we should probably pass off the initialization, and
	 * copying here?  can we hid that KERNEL_TAG_TYPE_MACLABEL is
	 * special from the mbuf code?
	 */
	if (t != NULL &&
	    t->m_tag_id   == KERNEL_MODULE_TAG_ID &&
	    t->m_tag_type == KERNEL_TAG_TYPE_MACLABEL) {
		if (mac_mbuf_tag_init(p, how) != 0) {
			m_tag_free(p);
			return (NULL);
		}
		mac_mbuf_tag_copy(t, p);
	} else
#endif
	bcopy(t + 1, p + 1, t->m_tag_len); /* Copy the data */
	return p;
}

/*
 * Copy two tag chains. The destination mbuf (to) loses any attached
 * tags even if the operation fails. This should not be a problem, as
 * m_tag_copy_chain() is typically called with a newly-allocated
 * destination mbuf.
 */
int
m_tag_copy_chain(struct mbuf *to, struct mbuf *from, int how)
{
	struct m_tag *p, *t, *tprev = NULL;

	KASSERT(to && from,
		("m_tag_copy: null argument, to %p from %p", to, from));
	m_tag_delete_chain(to, NULL);
	SLIST_FOREACH(p, &from->m_pkthdr.tags, m_tag_link) {
		t = m_tag_copy(p, how);
		if (t == NULL) {
			m_tag_delete_chain(to, NULL);
			return 0;
		}
		if (tprev == NULL)
			SLIST_INSERT_HEAD(&to->m_pkthdr.tags, t, m_tag_link);
		else {
			SLIST_INSERT_AFTER(tprev, t, m_tag_link);
			tprev = t;
		}
	}
	return 1;
}

/* Initialize tags on an mbuf. */
void
m_tag_init(struct mbuf *m)
{
	SLIST_INIT(&m->m_pkthdr.tags);
#if PF_PKTHDR
	bzero(&m->m_pkthdr.pf_mtag, sizeof (m->m_pkthdr.pf_mtag));
#endif
}

/* Get first tag in chain. */
struct m_tag *
m_tag_first(struct mbuf *m)
{
	return SLIST_FIRST(&m->m_pkthdr.tags);
}

/* Get next tag in chain. */
struct m_tag *
m_tag_next(__unused struct mbuf *m, struct m_tag *t)
{
	return SLIST_NEXT(t, m_tag_link);
}
