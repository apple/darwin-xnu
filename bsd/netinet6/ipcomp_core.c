/*	$FreeBSD: src/sys/netinet6/ipcomp_core.c,v 1.1.2.2 2001/07/03 11:01:54 ume Exp $	*/
/*	$KAME: ipcomp_core.c,v 1.24 2000/10/23 04:24:22 itojun Exp $	*/

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
#include <net/zlib.h>
#include <kern/cpu_number.h>

#include <netinet6/ipcomp.h>
#if INET6
#include <netinet6/ipcomp6.h>
#endif
#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif

#include <net/net_osdep.h>

static void *deflate_alloc(void *, u_int, u_int);
static void deflate_free(void *, void *);
static int deflate_common(struct mbuf *, struct mbuf *, size_t *, int);
static int deflate_compress(struct mbuf *, struct mbuf *, size_t *);
static int deflate_decompress(struct mbuf *, struct mbuf *, size_t *);

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

static z_stream	deflate_stream;
static z_stream	inflate_stream;

static const struct ipcomp_algorithm ipcomp_algorithms[] = {
	{ deflate_compress, deflate_decompress, 90 },
};

const struct ipcomp_algorithm *
ipcomp_algorithm_lookup(idx)
	int idx;
{

 	if (idx == SADB_X_CALG_DEFLATE) {
		/*
		 * Avert your gaze, ugly hack follows!
		 * We init here so our malloc can allocate using M_WAIT.
		 * We don't want to allocate if ipcomp isn't used, and we
		 * don't want to allocate on the input or output path.
		 * Allocation fails if we use M_NOWAIT because init allocates
		 * something like 256k (ouch).
		 */
		if (deflate_stream.zalloc == NULL) {
			deflate_stream.zalloc = deflate_alloc;
			deflate_stream.zfree = deflate_free;
			if (deflateInit2(&deflate_stream, deflate_policy, Z_DEFLATED,
					deflate_window_out, deflate_memlevel, Z_DEFAULT_STRATEGY)) {
				/* Allocation failed */
				bzero(&deflate_stream, sizeof(deflate_stream));
#if IPSEC_DEBUG
				printf("ipcomp_algorithm_lookup: deflateInit2 failed.\n");
#endif
			}
		}
		
		if (inflate_stream.zalloc == NULL) {
			inflate_stream.zalloc = deflate_alloc;
			inflate_stream.zfree = deflate_free;
			if (inflateInit2(&inflate_stream, deflate_window_in)) {
				/* Allocation failed */
				bzero(&inflate_stream, sizeof(inflate_stream));
#if IPSEC_DEBUG
				printf("ipcomp_algorithm_lookup: inflateInit2 failed.\n");
#endif
			}
		}

		return &ipcomp_algorithms[0];
	}
	return NULL;
}

static void *
deflate_alloc(aux, items, siz)
	void *aux;
	u_int items;
	u_int siz;
{
	void *ptr;
	ptr = _MALLOC(items * siz, M_TEMP, M_WAIT);
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
	struct mbuf *n = NULL, *n0 = NULL, **np;
	z_stream *zs;
	int error = 0;
	int zerror;
	size_t offset;

#define MOREBLOCK() \
do { \
	/* keep the reply buffer into our chain */		\
	if (n) {						\
		n->m_len = zs->total_out - offset;		\
		offset = zs->total_out;				\
		*np = n;					\
		np = &n->m_next;				\
		n = NULL;					\
	}							\
								\
	/* get a fresh reply buffer */				\
	MGET(n, M_DONTWAIT, MT_DATA);				\
	if (n) {						\
		MCLGET(n, M_DONTWAIT);				\
	}							\
	if (!n) {						\
		error = ENOBUFS;				\
		goto fail;					\
	}							\
	n->m_len = 0;						\
	n->m_len = M_TRAILINGSPACE(n);				\
	n->m_next = NULL;					\
	/*							\
	 * if this is the first reply buffer, reserve		\
	 * region for ipcomp header.				\
	 */							\
	if (*np == NULL) {					\
		n->m_len -= sizeof(struct ipcomp);		\
		n->m_data += sizeof(struct ipcomp);		\
	}							\
								\
	zs->next_out = mtod(n, u_int8_t *);			\
	zs->avail_out = n->m_len;				\
} while (0)

	for (mprev = m; mprev && mprev->m_next != md; mprev = mprev->m_next)
		;
	if (!mprev)
		panic("md is not in m in deflate_common");


	zs = mode ? &inflate_stream : &deflate_stream;
	if (zs->zalloc == NULL) {
		/*
		 * init is called in ipcomp_algorithm_lookup.
		 * if zs->zalloc is NULL, either init hasn't been called (unlikely)
		 * or init failed because of no memory.
		 */
		error = ENOBUFS;
		goto fail;
	}
	
	zs->next_in = 0;
	zs->avail_in = 0;
	zs->next_out = 0;
	zs->avail_out = 0;

	n0 = n = NULL;
	np = &n0;
	offset = 0;
	zerror = 0;
	p = md;
	while (p && p->m_len == 0) {
		p = p->m_next;
	}

	/* input stream and output stream are available */
	while (p && zs->avail_in == 0) {
		/* get input buffer */
		if (p && zs->avail_in == 0) {
			zs->next_in = mtod(p, u_int8_t *);
			zs->avail_in = p->m_len;
			p = p->m_next;
			while (p && p->m_len == 0) {
				p = p->m_next;
			}
		}

		/* get output buffer */
		if (zs->next_out == NULL || zs->avail_out == 0) {
			MOREBLOCK();
		}

		zerror = mode ? inflate(zs, Z_NO_FLUSH)
			      : deflate(zs, Z_NO_FLUSH);

		if (zerror == Z_STREAM_END)
			; /*once more.*/
		else if (zerror == Z_OK) {
			/* inflate: Z_OK can indicate the end of decode */
			if (mode && !p && zs->avail_out != 0)
				goto terminate;
			else
				; /*once more.*/
		} else {
			if (zs->msg) {
				ipseclog((LOG_ERR, "ipcomp_%scompress: "
				    "%sflate(Z_NO_FLUSH): %s\n",
				    mode ? "de" : "", mode ? "in" : "de",
				    zs->msg));
			} else {
				ipseclog((LOG_ERR, "ipcomp_%scompress: "
				    "%sflate(Z_NO_FLUSH): unknown error (%d)\n",
				    mode ? "de" : "", mode ? "in" : "de",
				    zerror));
			}
			mode ? inflateReset(zs) : deflateReset(zs);
/*			mode ? inflateEnd(zs) : deflateEnd(zs);*/
			error = EINVAL;
			goto fail;
		}
	}

	if (zerror == Z_STREAM_END)
		goto terminate;

	/* termination */
	while (1) {
		/* get output buffer */
		if (zs->next_out == NULL || zs->avail_out == 0) {
			MOREBLOCK();
		}

		zerror = mode ? inflate(zs, Z_FINISH)
			      : deflate(zs, Z_FINISH);

		if (zerror == Z_STREAM_END)
			break;
		else if (zerror == Z_OK)
			; /*once more.*/
		else {
			if (zs->msg) {
				ipseclog((LOG_ERR, "ipcomp_%scompress: "
				    "%sflate(Z_FINISH): %s\n",
				    mode ? "de" : "", mode ? "in" : "de",
				    zs->msg));
			} else {
				ipseclog((LOG_ERR, "ipcomp_%scompress: "
				    "%sflate(Z_FINISH): unknown error (%d)\n",
				    mode ? "de" : "", mode ? "in" : "de",
				    zerror));
			}
			mode ? inflateReset(zs) : deflateReset(zs);
/*			mode ? inflateEnd(zs) : deflateEnd(zs); */
			error = EINVAL;
			goto fail;
		}
	}

terminate:
	/* keep the final reply buffer into our chain */
	if (n) {
		n->m_len = zs->total_out - offset;
		offset = zs->total_out;
		*np = n;
		np = &n->m_next;
		n = NULL;
	}

	/* switch the mbuf to the new one */
	mprev->m_next = n0;
	m_freem(md);
	*lenp = zs->total_out;

	/* reset the inflate/deflate state */
	zerror = mode ? inflateReset(zs) : deflateReset(zs);
	if (zerror != Z_OK) {
		/*
		 * A failure here is uncommon. If this does
		 * fail, the packet can still be used but
		 * the z_stream will be messed up so subsequent
		 * inflates/deflates will probably fail.
		 */
		if (zs->msg) {
			ipseclog((LOG_ERR, "ipcomp_%scompress: "
			    "%sflateEnd: %s\n",
			    mode ? "de" : "", mode ? "in" : "de",
			    zs->msg));
		} else {
			ipseclog((LOG_ERR, "ipcomp_%scompress: "
			    "%sflateEnd: unknown error (%d)\n",
			    mode ? "de" : "", mode ? "in" : "de",
			    zerror));
		}
	}

	return 0;

fail:
	if (m)
		m_freem(m);
	if (n)
		m_freem(n);
	if (n0)
		m_freem(n0);
	return error;
#undef MOREBLOCK
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
