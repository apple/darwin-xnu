/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

/*	$KAME: keydb.c,v 1.61 2000/03/25 07:24:13 sumikawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/errno.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>

#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <netinet6/ipsec.h>

#include <net/net_osdep.h>

extern lck_mtx_t  *sadb_mutex;

MALLOC_DEFINE(M_SECA, "key mgmt", "security associations, key management");

// static void keydb_delsecasvar(struct secasvar *); // not used

/*
 * secpolicy management
 */
struct secpolicy *
keydb_newsecpolicy(void)
{
	struct secpolicy *p;

	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);

	return (struct secpolicy *)_MALLOC(sizeof(*p), M_SECA,
	    M_WAITOK | M_ZERO);
}

void
keydb_delsecpolicy(struct secpolicy *p)
{
	_FREE(p, M_SECA);
}

/*
 * secashead management
 */
struct secashead *
keydb_newsecashead(void)
{
	struct secashead *p;
	int i;

	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	p = (struct secashead *)_MALLOC(sizeof(*p), M_SECA, M_NOWAIT | M_ZERO);
	if (!p) {
		lck_mtx_unlock(sadb_mutex);
		p = (struct secashead *)_MALLOC(sizeof(*p), M_SECA,
		    M_WAITOK | M_ZERO);
		lck_mtx_lock(sadb_mutex);
	}
	if (!p) 
		return p;
	for (i = 0; i < sizeof(p->savtree)/sizeof(p->savtree[0]); i++)
		LIST_INIT(&p->savtree[i]);
	return p;
}

#if 0
void
keydb_delsecashead(p)
	struct secashead *p;
{

	_FREE(p, M_SECA);
}



/* 
 * secasvar management (reference counted)
 */
struct secasvar *
keydb_newsecasvar()
{
	struct secasvar *p;

	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);

	p = (struct secasvar *)_MALLOC(sizeof(*p), M_SECA, M_WAITOK);
	if (!p)
		return p;
	bzero(p, sizeof(*p));
	p->refcnt = 1;
	return p;
}

void
keydb_refsecasvar(p)
	struct secasvar *p;
{

	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	p->refcnt++;
}

void
keydb_freesecasvar(p)
	struct secasvar *p;
{

	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	p->refcnt--;
	/* negative refcnt will cause panic intentionally */
	if (p->refcnt <= 0)
		keydb_delsecasvar(p);
}

static void
keydb_delsecasvar(p)
	struct secasvar *p;
{

	if (p->refcnt)
		panic("keydb_delsecasvar called with refcnt != 0");

	_FREE(p, M_SECA);
}
#endif

/*
 * secreplay management
 */
struct secreplay *
keydb_newsecreplay(size_t wsize)
{
	struct secreplay *p;
	
	LCK_MTX_ASSERT(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	p = (struct secreplay *)_MALLOC(sizeof(*p), M_SECA, M_NOWAIT | M_ZERO);
	if (!p) {
		lck_mtx_unlock(sadb_mutex);
		p = (struct secreplay *)_MALLOC(sizeof(*p), M_SECA,
		    M_WAITOK | M_ZERO);
		lck_mtx_lock(sadb_mutex);
	}
	if (!p)
		return p;

	if (wsize != 0) {
		p->bitmap = (caddr_t)_MALLOC(wsize, M_SECA, M_NOWAIT | M_ZERO);
		if (!p->bitmap) {
			lck_mtx_unlock(sadb_mutex);
			p->bitmap = (caddr_t)_MALLOC(wsize, M_SECA,
			    M_WAITOK | M_ZERO);
			lck_mtx_lock(sadb_mutex);
			if (!p->bitmap) {
				_FREE(p, M_SECA);
				return NULL;
			}
		}
	}
	p->wsize = wsize;
	return p;
}

void
keydb_delsecreplay(struct secreplay *p)
{
	if (p->bitmap)
		_FREE(p->bitmap, M_SECA);
	_FREE(p, M_SECA);
}

#if 0
/*	NOT USED
 * secreg management
 */
struct secreg *
keydb_newsecreg()
{
	struct secreg *p;

	p = (struct secreg *)_MALLOC(sizeof(*p), M_SECA, M_WAITOK);
	if (p)
		bzero(p, sizeof(*p));
	return p;
}

void
keydb_delsecreg(p)
	struct secreg *p;
{

	_FREE(p, M_SECA);
}
#endif
