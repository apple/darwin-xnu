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
 *	@(#)hd_debug.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>

#include <net/if.h>

#include <netccitt/hdlc.h>
#include <netccitt/hd_var.h>
#include <netccitt/x25.h>

#ifdef HDLCDEBUG
#define NTRACE		32

struct	hdlctrace {
	struct	hdcb *ht_hdp;
	short	ht_dir;
	struct	mbuf *ht_frame;
	struct	timeval ht_time;
} hdtrace[NTRACE];

int	lasttracelogged, freezetrace;
#endif

hd_trace (hdp, direction, frame)
struct hdcb *hdp;
register struct Hdlc_frame *frame;
{
	register char *s;
	register int nr, pf, ns, i;
	struct Hdlc_iframe *iframe = (struct Hdlc_iframe *) frame;

#ifdef HDLCDEBUG
	hd_savetrace (hdp, direction, frame);
#endif
	if (hdp -> hd_xcp -> xc_ltrace) {
		if (direction == RX)
			printf ("F-In:  ");
		else if (direction == 2)
				printf ("F-Xmt: ");
			else
				printf ("F-Out:   ");

		nr = iframe -> nr;
		pf = iframe -> pf;
		ns = iframe -> ns;

		switch (hd_decode (hdp, frame)) {
		case SABM: 
			printf ("SABM   : PF=%d\n", pf);
			break;

		case DISC: 
			printf ("DISC   : PF=%d\n", pf);
			break;

		case DM: 
			printf ("DM     : PF=%d\n", pf);
			break;

		case FRMR: 
			{
			register struct Frmr_frame *f = (struct Frmr_frame *)frame;

			printf ("FRMR   : PF=%d, TEXT=", pf);
			for (s = (char *) frame, i = 0; i < 5; ++i, ++s)
				printf ("%x ", (int) * s & 0xff);
			printf ("\n");
			printf ("control=%x v(s)=%d v(r)=%d w%d x%d y%d z%d\n",
				f->frmr_control, f->frmr_ns, f->frmr_nr,
				f->frmr_w, f->frmr_x, f->frmr_y, f->frmr_z);
			break;
			}

		case UA: 
			printf ("UA     : PF=%d\n", pf);
			break;

		case RR: 
			printf ("RR     : N(R)=%d, PF=%d\n", nr, pf);
			break;

		case RNR: 
			printf ("RNR    : N(R)=%d, PF=%d\n", nr, pf);
			break;

		case REJ: 
			printf ("REJ    : N(R)=%d, PF=%d\n", nr, pf);
			break;

		case IFRAME: 
			{
			register struct mbuf *m;
			register int len = 0;

			for(m = dtom (frame); m; m = m -> m_next)
				len += m -> m_len;
			len -= HDHEADERLN;
			printf ("IFRAME : N(R)=%d, PF=%d, N(S)=%d, DATA(%d)=",
				nr, pf, ns, len);
			for (s = (char *)iframe->i_field, i = 0; i < 3; ++i, ++s)
				printf ("%x ", (int) *s & 0xff);
			printf ("\n");
			break;
			}

		default: 
			printf ("ILLEGAL: ");
			for (s = (char *) frame, i = 0; i < 5; ++i, ++s)
				printf ("%x ", (int) *s & 0xff);
			printf ("\n");
		}

	}
}

#ifdef HDLCDEBUG
static
hd_savetrace (hdp, dir, frame)
struct hdcb *hdp;
struct Hdlc_frame *frame;
{
	register struct hdlctrace *htp;
	register struct mbuf *m;

	if (freezetrace)
		return;
	htp = &hdtrace[lasttracelogged];
	lasttracelogged = (lasttracelogged + 1) % NTRACE;
	if (m = htp->ht_frame)
		m_freem (m);
	m = dtom (frame);
	htp->ht_frame = m_copy (m, 0, m->m_len);
	htp->ht_hdp = hdp;
	htp->ht_dir = dir;
	htp->ht_time = time;
}

hd_dumptrace (hdp)
struct hdcb *hdp;
{
	register int i, ltrace;
	register struct hdlctrace *htp;

	freezetrace = 1;
	hd_status (hdp);
	printf ("retransmit queue:");
	for (i = 0; i < 8; i++)
		printf (" %x", hdp -> hd_retxq[i]);
	printf ("\n");
	ltrace = hdp -> hd_xcp -> xc_ltrace;
	hdp -> hd_xcp -> xc_ltrace = 1;
	for (i = 0; i < NTRACE; i++) {
		htp = &hdtrace[(lasttracelogged + i) % NTRACE];
		if (htp->ht_hdp != hdp || htp->ht_frame == 0)
			continue;
		printf ("%d/%d	", htp->ht_time.tv_sec & 0xff,
			htp->ht_time.tv_usec / 10000);
		hd_trace (htp->ht_hdp, htp->ht_dir,
			mtod (htp->ht_frame, struct Hdlc_frame *));
		m_freem (htp->ht_frame);
		htp->ht_frame = 0;
	}
	hdp -> hd_xcp -> xc_ltrace = ltrace;
	freezetrace = 0;
}
#endif
