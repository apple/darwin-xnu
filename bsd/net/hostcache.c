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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/socket.h>

#include <net/hostcache.h>
#include <net/route.h>

MALLOC_DEFINE(M_HOSTCACHE, "hostcache", "per-host cache structure");

static	struct hctable hctable[AF_MAX];
static	int hc_timeout_interval = 120;
static	int hc_maxidle = 1800;

static	int cmpsa(const struct sockaddr *sa1, const struct sockaddr *sa2);
static	void hc_timeout(void *xhct);
static	void maybe_bump_hash(struct hctable *hct);

int
hc_init(int af, struct hccallback *hccb, int init_nelem, int primes)
{
	struct hctable *hct;
	struct hchead *heads;
	u_long nelem;

	hct = &hctable[af];
	nelem = init_nelem;
	if (hct->hct_nentries)
		return 0;

	if (primes) {
		heads = phashinit(init_nelem, M_HOSTCACHE, &nelem);
	} else {
		int i;
		MALLOC(heads, struct hchead *, nelem * sizeof *heads,
		       M_HOSTCACHE, M_WAITOK);
		for (i = 0; i < nelem; i++) {
			LIST_INIT(&heads[i]);
		}
	}
	
	hct->hct_heads = heads;
	hct->hct_nentries = nelem;
	hct->hct_primes = primes;
	timeout(hc_timeout, hct, hc_timeout_interval * hz);
	return 0;
}

struct hcentry *
hc_get(struct sockaddr *sa)
{
	u_long hash;
	struct hcentry *hc;
	struct hctable *hct;
	int s;

	hct = &hctable[sa->sa_family];
	if (hct->hct_nentries == 0)
		return 0;
	hash = hct->hct_cb->hccb_hash(sa, hct->hct_nentries);
	hc = hct->hct_heads[hash].lh_first;
	for (; hc; hc = hc->hc_link.le_next) {
		if (cmpsa(hc->hc_host, sa) == 0)
			break;
	}
	if (hc == 0)
		return 0;
	s = splnet();
	if (hc->hc_rt && (hc->hc_rt->rt_flags & RTF_UP) == 0) {
		RTFREE(hc->hc_rt);
		hc->hc_rt = 0;
	}
	if (hc->hc_rt == 0) {
		hc->hc_rt = rtalloc1(hc->hc_host, 1, 0);
	}
	hc_ref(hc);
	splx(s);
	/* XXX move to front of list? */
	return hc;
}

void
hc_ref(struct hcentry *hc)
{
	int s = splnet();
	if (hc->hc_refcnt++ == 0) {
		hc->hc_hct->hct_idle--;
		hc->hc_hct->hct_active++;
	}
	splx(s);
}

void
hc_rele(struct hcentry *hc)
{
	int s = splnet();
#ifdef DIAGNOSTIC
	printf("hc_rele: %p: negative refcnt!\n", (void *)hc);
#endif
	hc->hc_refcnt--;
	if (hc->hc_refcnt == 0) {
		hc->hc_hct->hct_idle++;
		hc->hc_hct->hct_active--;
		hc->hc_idlesince = mono_time; /* XXX right one? */
	}
	splx(s);
}

/*
 * The user is expected to initialize hc_host with the address and everything
 * else to the appropriate form of `0'.
 */
int
hc_insert(struct hcentry *hc)
{
	struct hcentry *hc2;
	struct hctable *hct;
	u_long hash;
	int s;

	hct = &hctable[hc->hc_host->sa_family];
	hash = hct->hct_cb->hccb_hash(hc->hc_host, hct->hct_nentries);
	
	hc2 = hct->hct_heads[hash].lh_first;
	for (; hc2; hc2 = hc2->hc_link.le_next) {
		if (cmpsa(hc2->hc_host, hc->hc_host) == 0)
			break;
	}
	if (hc2 != 0)
		return EEXIST;
	hc->hc_hct = hct;
	s = splnet();
	LIST_INSERT_HEAD(&hct->hct_heads[hash], hc, hc_link);
	hct->hct_idle++;
	/*
	 * If the table is now more than 75% full, consider bumping it.
	 */
	if (100 * (hct->hct_idle + hct->hct_active) > 75 * hct->hct_nentries)
		maybe_bump_hash(hct);
	splx(s);
	return 0;
}

/*
 * It's not clear to me how much sense this makes as an external interface,
 * since it is expected that the deletion will normally be handled by
 * the cache timeout.
 */
int
hc_delete(struct hcentry *hc)
{
	struct hctable *hct;
	int error, s;

	if (hc->hc_refcnt > 0)
		return 0;

	hct = hc->hc_hct;
	error = hct->hct_cb->hccb_delete(hc);
	if (error)
		return 0;

	s = splnet();
	LIST_REMOVE(hc, hc_link);
	hc->hc_hct->hct_idle--;
	splx(s);
	FREE(hc, M_HOSTCACHE);
	return 0;
}

static void
hc_timeout(void *xhct)
{
	struct hcentry *hc;
	struct hctable *hct;
	int j, s;
	time_t start;

	hct = xhct;
	start = mono_time.tv_sec; /* for simplicity */

	if (hct->hct_idle == 0)
		return;
	for (j = 0; j < hct->hct_nentries; j++) {
		for (hc = hct->hct_heads[j].lh_first; hc; 
		     hc = hc->hc_link.le_next) {
			if (hc->hc_refcnt > 0)
				continue;
			if (hc->hc_idlesince.tv_sec + hc_maxidle <= start) {
				if (hct->hct_cb->hccb_delete(hc))
					continue;
				s = splnet();
				LIST_REMOVE(hc, hc_link);
				hct->hct_idle--;
				splx(s);
			}
		}
	}
	/*
	 * Fiddle something here based on tot_idle...
	 */
	timeout(hc_timeout, xhct, hc_timeout_interval * hz);
}

static int
cmpsa(const struct sockaddr *sa1, const struct sockaddr *sa2)
{
	if (sa1->sa_len != sa2->sa_len)
		return ((int)sa1->sa_len - sa2->sa_len);
	return bcmp(sa1, sa2, sa1->sa_len);
}

static void
maybe_bump_hash(struct hctable *hct)
{
	;			/* XXX fill me in */
}
