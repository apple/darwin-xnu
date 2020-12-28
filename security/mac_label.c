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

static zone_t zone_label;

void
mac_labelzone_init(void)
{
	zone_label = zinit(sizeof(struct label),
	    8192 * sizeof(struct label),
	    sizeof(struct label), "MAC Labels");
	zone_change(zone_label, Z_EXPAND, TRUE);
	zone_change(zone_label, Z_EXHAUST, FALSE);
	zone_change(zone_label, Z_CALLERACCT, FALSE);
}

struct label *
mac_labelzone_alloc(int flags)
{
	struct label *l;

	if (flags & MAC_NOWAIT) {
		l = (struct label *) zalloc_noblock(zone_label);
	} else {
		l = (struct label *) zalloc(zone_label);
	}
	if (l == NULL) {
		return NULL;
	}

	bzero(l, sizeof(struct label));
	l->l_flags = MAC_FLAG_INITIALIZED;
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
