/*	$KAME: ipcomp_core.c,v 1.10 2000/02/22 14:04:23 itojun Exp $	*/

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
 * RFC2393 IP payload compression protocol (IPComp).
 */

#define _IP_VHL
#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/route.h>
#include <net/netisr.h>
#include <net/zlib.h>
#include <kern/cpu_number.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet6/ipcomp.h>
#include <netinet6/ipsec.h>

#include <net/net_osdep.h>

static void *deflate_alloc __P((void *, u_int, u_int));
static void deflate_free __P((void *, void *));
static int deflate_common __P((struct mbuf *, struct mbuf *, size_t *, int));
static int deflate_compress __P((struct mbuf *, struct mbuf *, size_t *));
static int deflate_decompress __P((struct mbuf *, struct mbuf *, size_t *));

/*
 * We need to use default window size (2^15 = 32Kbytes as of writing) for
 * inbound case.  Otherwise we get interop problem.
 * Use negative value to avoid Adler32 checksum.  This is an undocumented
 * feature in zlib (see ipsec wg mailing list archive in January 2000).
 */
static int deflate_policy = Z_DEFAULT_COMPRESSION;
static int deflate_window_out = -12;
static const int deflate_window_in = -1 * MAX_WBITS;	/* don't change it */
static int deflate_memlevel = MAX_MEM_LEVEL;

struct ipcomp_algorithm ipcomp_algorithms[] = {
	{ NULL, NULL, -1 },
	{ NULL, NULL, -1 },
	{ deflate_compress, deflate_decompress, 90 },
	{ NULL, NULL, 90 },
};

static void *
deflate_alloc(aux, items, siz)
	void *aux;
	u_int items;
	u_int siz;
{
	void *ptr;
	MALLOC(ptr, void *, items * siz, M_TEMP, M_NOWAIT);
	return ptr;
}

static void
deflate_free(aux, ptr)
	void *aux;
	void *ptr;
{
	FREE(ptr, M_TEMP);
}

static int
deflate_common(m, md, lenp, mode)
	struct mbuf *m;
	struct mbuf *md;
	size_t *lenp;
	int mode;	/* 0: compress 1: decompress */
{
	struct mbuf *mprev;
	struct mbuf *p;
	struct mbuf *n, *n0 = NULL, **np;
	z_stream zs;
	int error = 0;
	int zerror;
	size_t offset;
	int firsttime, final, flush;

	for (mprev = m; mprev && mprev->m_next != md; mprev = mprev->m_next)
		;
	if (!mprev)
		panic("md is not in m in deflate_common");

	bzero(&zs, sizeof(zs));
	zs.zalloc = deflate_alloc;
	zs.zfree = deflate_free;

	zerror = mode ? inflateInit2(&zs, deflate_window_in)
		      : deflateInit2(&zs, deflate_policy, Z_DEFLATED,
				deflate_window_out, deflate_memlevel,
				Z_DEFAULT_STRATEGY);
	if (zerror != Z_OK) {
		error = ENOBUFS;
		goto fail;
	}

	n0 = n = NULL;
	np = &n0;
	offset = 0;
	firsttime = 1;
	final = 0;
	flush = Z_NO_FLUSH;
	zerror = 0;
	p = md;
	while (1) {
		/*
		 * first time, we need to setup the buffer before calling
		 * compression function.
		 */
		if (firsttime)
			firsttime = 0;
		else {
			zerror = mode ? inflate(&zs, flush)
				      : deflate(&zs, flush);
		}

		/* get input buffer */
		if (p && zs.avail_in == 0) {
			zs.next_in = mtod(p, u_int8_t *);
			zs.avail_in = p->m_len;
			p = p->m_next;
			if (!p) {
				final = 1;
				flush = Z_PARTIAL_FLUSH;
			}
		}

		/* get output buffer */
		if (zs.next_out == NULL || zs.avail_out == 0) {
			/* keep the reply buffer into our chain */
			if (n) {
				n->m_len = zs.total_out - offset;
				offset = zs.total_out;
				*np = n;
				np = &n->m_next;
			}

			/* get a fresh reply buffer */
			MGET(n, M_DONTWAIT, MT_DATA);
			if (n) {
				MCLGET(n, M_DONTWAIT);
			}
			if (!n) {
				error = ENOBUFS;
				goto fail;
			}
			n->m_len = 0;
			n->m_len = M_TRAILINGSPACE(n);
			n->m_next = NULL;
			/*
			 * if this is the first reply buffer, reserve
			 * region for ipcomp header.
			 */
			if (*np == NULL) {
				n->m_len -= sizeof(struct ipcomp);
				n->m_data += sizeof(struct ipcomp);
			}

			zs.next_out = mtod(n, u_int8_t *);
			zs.avail_out = n->m_len;
		}

		if (zerror == Z_OK) {
			/*
			 * to terminate deflate/inflate process, we need to
			 * call {in,de}flate() with different flushing methods.
			 *
			 * deflate() needs at least one Z_PARTIAL_FLUSH,
			 * then use Z_FINISH until we get to the end.
			 * (if we use Z_FLUSH without Z_PARTIAL_FLUSH, deflate()
			 * will assume contiguous single output buffer, and that
			 * is not what we want)
			 * inflate() does not care about flushing method, but
			 * needs output buffer until it gets to the end.
			 *
			 * the most outer loop will be terminated with
			 * Z_STREAM_END.
			 */
			if (final == 1) {
				/* reached end of mbuf chain */
				if (mode == 0)
					final = 2;
				else
					final = 3;
			} else if (final == 2) {
				/* terminate deflate case */
				flush = Z_FINISH;
			} else if (final == 3) {
				/* terminate inflate case */
				;
			}
		} else if (zerror == Z_STREAM_END)
			break;
		else {
			ipseclog((LOG_ERR, "ipcomp_%scompress: %sflate: %s\n",
				mode ? "de" : "", mode ? "in" : "de",
				zs.msg ? zs.msg : "unknown error"));
			error = EINVAL;
			goto fail;
		}
	}
	zerror = mode ? inflateEnd(&zs) : deflateEnd(&zs);
	if (zerror != Z_OK) {
		ipseclog((LOG_ERR, "ipcomp_%scompress: %sflate: %s\n",
			mode ? "de" : "", mode ? "in" : "de",
			zs.msg ? zs.msg : "unknown error"));
		error = EINVAL;
		goto fail;
	}
	/* keep the final reply buffer into our chain */
	if (n) {
		n->m_len = zs.total_out - offset;
		offset = zs.total_out;
		*np = n;
		np = &n->m_next;
	}

	/* switch the mbuf to the new one */
	mprev->m_next = n0;
	m_freem(md);
	*lenp = zs.total_out;

	return 0;

fail:
	if (m)
		m_freem(m);
	if (n0)
		m_freem(n0);
	return error;
}

static int
deflate_compress(m, md, lenp)
	struct mbuf *m;
	struct mbuf *md;
	size_t *lenp;
{
	if (!m)
		panic("m == NULL in deflate_compress");
	if (!md)
		panic("md == NULL in deflate_compress");
	if (!lenp)
		panic("lenp == NULL in deflate_compress");

	return deflate_common(m, md, lenp, 0);
}

static int
deflate_decompress(m, md, lenp)
	struct mbuf *m;
	struct mbuf *md;
	size_t *lenp;
{
	if (!m)
		panic("m == NULL in deflate_decompress");
	if (!md)
		panic("md == NULL in deflate_decompress");
	if (!lenp)
		panic("lenp == NULL in deflate_decompress");

	return deflate_common(m, md, lenp, 1);
}
