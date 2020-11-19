/*-
 * Copyright (c) 2004 Networks Associates Technology, Inc.
 * Copyright (c) 2005 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <kern/zalloc.h>
#include <security/_label.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <security/mac_internal.h>

static ZONE_DECLARE(zone_label, "MAC Labels", sizeof(struct label), ZC_ZFREE_CLEARMEM);

struct label *
mac_labelzone_alloc(int flags)
{
	int zflags = Z_ZERO | (flags & MAC_NOWAIT);
	struct label *l;

	static_assert(MAC_NOWAIT == Z_NOWAIT);
	l = zalloc_flags(zone_label, zflags);
	if (l) {
		l->l_flags = MAC_FLAG_INITIALIZED;
	}
	return l;
}

void
mac_labelzone_free(struct label *l)
{
	if (l == NULL) {
		panic("Free of NULL MAC label\n");
	}

	if ((l->l_flags & MAC_FLAG_INITIALIZED) == 0) {
		panic("Free of uninitialized label\n");
	}
	bzero(l, sizeof(struct label));
	zfree(zone_label, l);
}

/*
 * Functions used by policy modules to get and set label values.
 */
intptr_t
mac_label_get(struct label *l, int slot)
{
	KASSERT(l != NULL, ("mac_label_get: NULL label"));

	return (intptr_t) (l->l_perpolicy[slot].l_ptr);
}

void
mac_label_set(struct label *l, int slot, intptr_t v)
{
	KASSERT(l != NULL, ("mac_label_set: NULL label"));

	l->l_perpolicy[slot].l_ptr = (void *) v;
}
