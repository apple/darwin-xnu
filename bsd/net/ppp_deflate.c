/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * ppp_deflate.c - interface the zlib procedures for Deflate compression
 * and decompression (as used by gzip) to the PPP code.
 * This version is for use with mbufs on BSD-derived systems.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <net/ppp_defs.h>
#include <net/zlib.h>

#define PACKETPTR	struct mbuf *
#include <net/ppp_comp.h>

#if DO_DEFLATE

#define DEFLATE_DEBUG	1

/*
 * State for a Deflate (de)compressor.
 */
struct deflate_state {
    int		seqno;
    int		w_size;
    int		unit;
    int		hdrlen;
    int		mru;
    int		debug;
    z_stream	strm;
    struct compstat stats;
};

#define DEFLATE_OVHD	2		/* Deflate overhead/packet */

static void	*z_alloc __P((void *, u_int items, u_int size));
static void	z_free __P((void *, void *ptr));
static void	*z_comp_alloc __P((u_char *options, int opt_len));
static void	*z_decomp_alloc __P((u_char *options, int opt_len));
static void	z_comp_free __P((void *state));
static void	z_decomp_free __P((void *state));
static int	z_comp_init __P((void *state, u_char *options, int opt_len,
				 int unit, int hdrlen, int debug));
static int	z_decomp_init __P((void *state, u_char *options, int opt_len,
				     int unit, int hdrlen, int mru, int debug));
static int	z_compress __P((void *state, struct mbuf **mret,
				  struct mbuf *mp, int slen, int maxolen));
static void	z_incomp __P((void *state, struct mbuf *dmsg));
static int	z_decompress __P((void *state, struct mbuf *cmp,
				    struct mbuf **dmpp));
static void	z_comp_reset __P((void *state));
static void	z_decomp_reset __P((void *state));
static void	z_comp_stats __P((void *state, struct compstat *stats));

/*
 * Procedures exported to if_ppp.c.
 */
struct compressor ppp_deflate = {
    CI_DEFLATE,			/* compress_proto */
    z_comp_alloc,		/* comp_alloc */
    z_comp_free,		/* comp_free */
    z_comp_init,		/* comp_init */
    z_comp_reset,		/* comp_reset */
    z_compress,			/* compress */
    z_comp_stats,		/* comp_stat */
    z_decomp_alloc,		/* decomp_alloc */
    z_decomp_free,		/* decomp_free */
    z_decomp_init,		/* decomp_init */
    z_decomp_reset,		/* decomp_reset */
    z_decompress,		/* decompress */
    z_incomp,			/* incomp */
    z_comp_stats,		/* decomp_stat */
};

struct compressor ppp_deflate_draft = {
    CI_DEFLATE_DRAFT,		/* compress_proto */
    z_comp_alloc,		/* comp_alloc */
    z_comp_free,		/* comp_free */
    z_comp_init,		/* comp_init */
    z_comp_reset,		/* comp_reset */
    z_compress,			/* compress */
    z_comp_stats,		/* comp_stat */
    z_decomp_alloc,		/* decomp_alloc */
    z_decomp_free,		/* decomp_free */
    z_decomp_init,		/* decomp_init */
    z_decomp_reset,		/* decomp_reset */
    z_decompress,		/* decompress */
    z_incomp,			/* incomp */
    z_comp_stats,		/* decomp_stat */
};

/*
 * Space allocation and freeing routines for use by zlib routines.
 */
void *
z_alloc(notused, items, size)
    void *notused;
    u_int items, size;
{
    void *ptr;

    MALLOC(ptr, void *, items * size, M_DEVBUF, M_NOWAIT);
    return ptr;
}

void
z_free(notused, ptr)
    void *notused;
    void *ptr;
{
    FREE(ptr, M_DEVBUF);
}

/*
 * Allocate space for a compressor.
 */
static void *
z_comp_alloc(options, opt_len)
    u_char *options;
    int opt_len;
{
    struct deflate_state *state;
    int w_size;

    if (opt_len != CILEN_DEFLATE
	|| (options[0] != CI_DEFLATE && options[0] != CI_DEFLATE_DRAFT)
	|| options[1] != CILEN_DEFLATE
	|| DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL
	|| options[3] != DEFLATE_CHK_SEQUENCE)
	return NULL;
    w_size = DEFLATE_SIZE(options[2]);
    if (w_size < DEFLATE_MIN_SIZE || w_size > DEFLATE_MAX_SIZE)
	return NULL;

    MALLOC(state, struct deflate_state *, sizeof(struct deflate_state),
	   M_DEVBUF, M_NOWAIT);
    if (state == NULL)
	return NULL;

    state->strm.next_in = NULL;
    state->strm.zalloc = z_alloc;
    state->strm.zfree = z_free;
    if (deflateInit2(&state->strm, Z_DEFAULT_COMPRESSION, DEFLATE_METHOD_VAL,
		     -w_size, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
	FREE(state, M_DEVBUF);
	return NULL;
    }

    state->w_size = w_size;
    bzero(&state->stats, sizeof(state->stats));
    return (void *) state;
}

static void
z_comp_free(arg)
    void *arg;
{
    struct deflate_state *state = (struct deflate_state *) arg;

    deflateEnd(&state->strm);
    FREE(state, M_DEVBUF);
}

static int
z_comp_init(arg, options, opt_len, unit, hdrlen, debug)
    void *arg;
    u_char *options;
    int opt_len, unit, hdrlen, debug;
{
    struct deflate_state *state = (struct deflate_state *) arg;

    if (opt_len < CILEN_DEFLATE
	|| (options[0] != CI_DEFLATE && options[0] != CI_DEFLATE_DRAFT)
	|| options[1] != CILEN_DEFLATE
	|| DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL
	|| DEFLATE_SIZE(options[2]) != state->w_size
	|| options[3] != DEFLATE_CHK_SEQUENCE)
	return 0;

    state->seqno = 0;
    state->unit = unit;
    state->hdrlen = hdrlen;
    state->debug = debug;

    deflateReset(&state->strm);

    return 1;
}

static void
z_comp_reset(arg)
    void *arg;
{
    struct deflate_state *state = (struct deflate_state *) arg;

    state->seqno = 0;
    deflateReset(&state->strm);
}

int
z_compress(arg, mret, mp, orig_len, maxolen)
    void *arg;
    struct mbuf **mret;		/* compressed packet (out) */
    struct mbuf *mp;		/* uncompressed packet (in) */
    int orig_len, maxolen;
{
    struct deflate_state *state = (struct deflate_state *) arg;
    u_char *rptr, *wptr;
    int proto, olen, wspace, r, flush;
    struct mbuf *m;

    /*
     * Check that the protocol is in the range we handle.
     */
    rptr = mtod(mp, u_char *);
    proto = PPP_PROTOCOL(rptr);
    if (proto > 0x3fff || proto == 0xfd || proto == 0xfb) {
	*mret = NULL;
	return orig_len;
    }

    /* Allocate one mbuf initially. */
    if (maxolen > orig_len)
	maxolen = orig_len;
    MGET(m, M_DONTWAIT, MT_DATA);
    *mret = m;
    if (m != NULL) {
	m->m_len = 0;
	if (maxolen + state->hdrlen > MLEN)
	    MCLGET(m, M_DONTWAIT);
	wspace = M_TRAILINGSPACE(m);
	if (state->hdrlen + PPP_HDRLEN + 2 < wspace) {
	    m->m_data += state->hdrlen;
	    wspace -= state->hdrlen;
	}
	wptr = mtod(m, u_char *);

	/*
	 * Copy over the PPP header and store the 2-byte sequence number.
	 */
	wptr[0] = PPP_ADDRESS(rptr);
	wptr[1] = PPP_CONTROL(rptr);
	wptr[2] = PPP_COMP >> 8;
	wptr[3] = PPP_COMP;
	wptr += PPP_HDRLEN;
	wptr[0] = state->seqno >> 8;
	wptr[1] = state->seqno;
	wptr += 2;
	state->strm.next_out = wptr;
	state->strm.avail_out = wspace - (PPP_HDRLEN + 2);
    } else {
	state->strm.next_out = NULL;
	state->strm.avail_out = 1000000;
	wptr = NULL;
	wspace = 0;
    }
    ++state->seqno;

    rptr += (proto > 0xff)? 2: 3;	/* skip 1st proto byte if 0 */
    state->strm.next_in = rptr;
    state->strm.avail_in = mtod(mp, u_char *) + mp->m_len - rptr;
    mp = mp->m_next;
    flush = (mp == NULL)? Z_PACKET_FLUSH: Z_NO_FLUSH;
    olen = 0;
    for (;;) {
	r = deflate(&state->strm, flush);
	if (r != Z_OK) {
	    printf("z_compress: deflate returned %d (%s)\n",
		   r, (state->strm.msg? state->strm.msg: ""));
	    break;
	}
	if (flush != Z_NO_FLUSH && state->strm.avail_out != 0)
	    break;		/* all done */
	if (state->strm.avail_in == 0 && mp != NULL) {
	    state->strm.next_in = mtod(mp, u_char *);
	    state->strm.avail_in = mp->m_len;
	    mp = mp->m_next;
	    if (mp == NULL)
		flush = Z_PACKET_FLUSH;
	}
	if (state->strm.avail_out == 0) {
	    if (m != NULL) {
		m->m_len = wspace;
		olen += wspace;
		MGET(m->m_next, M_DONTWAIT, MT_DATA);
		m = m->m_next;
		if (m != NULL) {
		    m->m_len = 0;
		    if (maxolen - olen > MLEN)
			MCLGET(m, M_DONTWAIT);
		    state->strm.next_out = mtod(m, u_char *);
		    state->strm.avail_out = wspace = M_TRAILINGSPACE(m);
		}
	    }
	    if (m == NULL) {
		state->strm.next_out = NULL;
		state->strm.avail_out = 1000000;
	    }
	}
    }
    if (m != NULL)
	olen += (m->m_len = wspace - state->strm.avail_out);

    /*
     * See if we managed to reduce the size of the packet.
     */
    if (m != NULL && olen < orig_len) {
	state->stats.comp_bytes += olen;
	state->stats.comp_packets++;
    } else {
	if (*mret != NULL) {
	    m_freem(*mret);
	    *mret = NULL;
	}
	state->stats.inc_bytes += orig_len;
	state->stats.inc_packets++;
	olen = orig_len;
    }
    state->stats.unc_bytes += orig_len;
    state->stats.unc_packets++;

    return olen;
}

static void
z_comp_stats(arg, stats)
    void *arg;
    struct compstat *stats;
{
    struct deflate_state *state = (struct deflate_state *) arg;
    u_int out;

    *stats = state->stats;
    stats->ratio = stats->unc_bytes;
    out = stats->comp_bytes + stats->inc_bytes;
    if (stats->ratio <= 0x7ffffff)
	stats->ratio <<= 8;
    else
	out >>= 8;
    if (out != 0)
	stats->ratio /= out;
}

/*
 * Allocate space for a decompressor.
 */
static void *
z_decomp_alloc(options, opt_len)
    u_char *options;
    int opt_len;
{
    struct deflate_state *state;
    int w_size;

    if (opt_len != CILEN_DEFLATE
	|| (options[0] != CI_DEFLATE && options[0] != CI_DEFLATE_DRAFT)
	|| options[1] != CILEN_DEFLATE
	|| DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL
	|| options[3] != DEFLATE_CHK_SEQUENCE)
	return NULL;
    w_size = DEFLATE_SIZE(options[2]);
    if (w_size < DEFLATE_MIN_SIZE || w_size > DEFLATE_MAX_SIZE)
	return NULL;

    MALLOC(state, struct deflate_state *, sizeof(struct deflate_state),
	   M_DEVBUF, M_NOWAIT);
    if (state == NULL)
	return NULL;

    state->strm.next_out = NULL;
    state->strm.zalloc = z_alloc;
    state->strm.zfree = z_free;
    if (inflateInit2(&state->strm, -w_size) != Z_OK) {
	FREE(state, M_DEVBUF);
	return NULL;
    }

    state->w_size = w_size;
    bzero(&state->stats, sizeof(state->stats));
    return (void *) state;
}

static void
z_decomp_free(arg)
    void *arg;
{
    struct deflate_state *state = (struct deflate_state *) arg;

    inflateEnd(&state->strm);
    FREE(state, M_DEVBUF);
}

static int
z_decomp_init(arg, options, opt_len, unit, hdrlen, mru, debug)
    void *arg;
    u_char *options;
    int opt_len, unit, hdrlen, mru, debug;
{
    struct deflate_state *state = (struct deflate_state *) arg;

    if (opt_len < CILEN_DEFLATE
	|| (options[0] != CI_DEFLATE && options[0] != CI_DEFLATE_DRAFT)
	|| options[1] != CILEN_DEFLATE
	|| DEFLATE_METHOD(options[2]) != DEFLATE_METHOD_VAL
	|| DEFLATE_SIZE(options[2]) != state->w_size
	|| options[3] != DEFLATE_CHK_SEQUENCE)
	return 0;

    state->seqno = 0;
    state->unit = unit;
    state->hdrlen = hdrlen;
    state->debug = debug;
    state->mru = mru;

    inflateReset(&state->strm);

    return 1;
}

static void
z_decomp_reset(arg)
    void *arg;
{
    struct deflate_state *state = (struct deflate_state *) arg;

    state->seqno = 0;
    inflateReset(&state->strm);
}

/*
 * Decompress a Deflate-compressed packet.
 *
 * Because of patent problems, we return DECOMP_ERROR for errors
 * found by inspecting the input data and for system problems, but
 * DECOMP_FATALERROR for any errors which could possibly be said to
 * be being detected "after" decompression.  For DECOMP_ERROR,
 * we can issue a CCP reset-request; for DECOMP_FATALERROR, we may be
 * infringing a patent of Motorola's if we do, so we take CCP down
 * instead.
 *
 * Given that the frame has the correct sequence number and a good FCS,
 * errors such as invalid codes in the input most likely indicate a
 * bug, so we return DECOMP_FATALERROR for them in order to turn off
 * compression, even though they are detected by inspecting the input.
 */
int
z_decompress(arg, mi, mop)
    void *arg;
    struct mbuf *mi, **mop;
{
    struct deflate_state *state = (struct deflate_state *) arg;
    struct mbuf *mo, *mo_head;
    u_char *rptr, *wptr;
    int rlen, olen, ospace;
    int seq, i, flush, r, decode_proto;
    u_char hdr[PPP_HDRLEN + DEFLATE_OVHD];

    *mop = NULL;
    rptr = mtod(mi, u_char *);
    rlen = mi->m_len;
    for (i = 0; i < PPP_HDRLEN + DEFLATE_OVHD; ++i) {
	while (rlen <= 0) {
	    mi = mi->m_next;
	    if (mi == NULL)
		return DECOMP_ERROR;
	    rptr = mtod(mi, u_char *);
	    rlen = mi->m_len;
	}
	hdr[i] = *rptr++;
	--rlen;
    }

    /* Check the sequence number. */
    seq = (hdr[PPP_HDRLEN] << 8) + hdr[PPP_HDRLEN+1];
    if (seq != state->seqno) {
	if (state->debug)
	    printf("z_decompress%d: bad seq # %d, expected %d\n",
		   state->unit, seq, state->seqno);
	return DECOMP_ERROR;
    }
    ++state->seqno;

    /* Allocate an output mbuf. */
    MGETHDR(mo, M_DONTWAIT, MT_DATA);
    if (mo == NULL)
	return DECOMP_ERROR;
    mo_head = mo;
    mo->m_len = 0;
    mo->m_next = NULL;
    MCLGET(mo, M_DONTWAIT);
    ospace = M_TRAILINGSPACE(mo);
    if (state->hdrlen + PPP_HDRLEN < ospace) {
	mo->m_data += state->hdrlen;
	ospace -= state->hdrlen;
    }

    /*
     * Fill in the first part of the PPP header.  The protocol field
     * comes from the decompressed data.
     */
    wptr = mtod(mo, u_char *);
    wptr[0] = PPP_ADDRESS(hdr);
    wptr[1] = PPP_CONTROL(hdr);
    wptr[2] = 0;

    /*
     * Set up to call inflate.  We set avail_out to 1 initially so we can
     * look at the first byte of the output and decide whether we have
     * a 1-byte or 2-byte protocol field.
     */
    state->strm.next_in = rptr;
    state->strm.avail_in = rlen;
    mi = mi->m_next;
    flush = (mi == NULL)? Z_PACKET_FLUSH: Z_NO_FLUSH;
    rlen += PPP_HDRLEN + DEFLATE_OVHD;
    state->strm.next_out = wptr + 3;
    state->strm.avail_out = 1;
    decode_proto = 1;
    olen = PPP_HDRLEN;

    /*
     * Call inflate, supplying more input or output as needed.
     */
    for (;;) {
	r = inflate(&state->strm, flush);
	if (r != Z_OK) {
#if !DEFLATE_DEBUG
	    if (state->debug)
#endif
		printf("z_decompress%d: inflate returned %d (%s)\n",
		       state->unit, r, (state->strm.msg? state->strm.msg: ""));
	    m_freem(mo_head);
	    return DECOMP_FATALERROR;
	}
	if (flush != Z_NO_FLUSH && state->strm.avail_out != 0)
	    break;		/* all done */
	if (state->strm.avail_in == 0 && mi != NULL) {
	    state->strm.next_in = mtod(mi, u_char *);
	    state->strm.avail_in = mi->m_len;
	    rlen += mi->m_len;
	    mi = mi->m_next;
	    if (mi == NULL)
		flush = Z_PACKET_FLUSH;
	}
	if (state->strm.avail_out == 0) {
	    if (decode_proto) {
		state->strm.avail_out = ospace - PPP_HDRLEN;
		if ((wptr[3] & 1) == 0) {
		    /* 2-byte protocol field */
		    wptr[2] = wptr[3];
		    --state->strm.next_out;
		    ++state->strm.avail_out;
		    --olen;
		}
		decode_proto = 0;
	    } else {
		mo->m_len = ospace;
		olen += ospace;
		MGET(mo->m_next, M_DONTWAIT, MT_DATA);
		mo = mo->m_next;
		if (mo == NULL) {
		    m_freem(mo_head);
		    return DECOMP_ERROR;
		}
		MCLGET(mo, M_DONTWAIT);
		state->strm.next_out = mtod(mo, u_char *);
		state->strm.avail_out = ospace = M_TRAILINGSPACE(mo);
	    }
	}
    }
    if (decode_proto) {
	m_freem(mo_head);
	return DECOMP_ERROR;
    }
    olen += (mo->m_len = ospace - state->strm.avail_out);
#if DEFLATE_DEBUG
    if (state->debug && olen > state->mru + PPP_HDRLEN)
	printf("ppp_deflate%d: exceeded mru (%d > %d)\n",
	       state->unit, olen, state->mru + PPP_HDRLEN);
#endif

    state->stats.unc_bytes += olen;
    state->stats.unc_packets++;
    state->stats.comp_bytes += rlen;
    state->stats.comp_packets++;

    *mop = mo_head;
    return DECOMP_OK;
}

/*
 * Incompressible data has arrived - add it to the history.
 */
static void
z_incomp(arg, mi)
    void *arg;
    struct mbuf *mi;
{
    struct deflate_state *state = (struct deflate_state *) arg;
    u_char *rptr;
    int rlen, proto, r;

    /*
     * Check that the protocol is one we handle.
     */
    rptr = mtod(mi, u_char *);
    proto = PPP_PROTOCOL(rptr);
    if (proto > 0x3fff || proto == 0xfd || proto == 0xfb)
	return;

    ++state->seqno;

    /*
     * Iterate through the mbufs, adding the characters in them
     * to the decompressor's history.  For the first mbuf, we start
     * at the either the 1st or 2nd byte of the protocol field,
     * depending on whether the protocol value is compressible.
     */
    rlen = mi->m_len;
    state->strm.next_in = rptr + 3;
    state->strm.avail_in = rlen - 3;
    if (proto > 0xff) {
	--state->strm.next_in;
	++state->strm.avail_in;
    }
    for (;;) {
	r = inflateIncomp(&state->strm);
	if (r != Z_OK) {
	    /* gak! */
#if !DEFLATE_DEBUG
	    if (state->debug)
#endif
		printf("z_incomp%d: inflateIncomp returned %d (%s)\n",
		       state->unit, r, (state->strm.msg? state->strm.msg: ""));
	    return;
	}
	mi = mi->m_next;
	if (mi == NULL)
	    break;
	state->strm.next_in = mtod(mi, u_char *);
	state->strm.avail_in = mi->m_len;
	rlen += mi->m_len;
    }

    /*
     * Update stats.
     */
    state->stats.inc_bytes += rlen;
    state->stats.inc_packets++;
    state->stats.unc_bytes += rlen;
    state->stats.unc_packets++;
}

#endif /* DO_DEFLATE */
