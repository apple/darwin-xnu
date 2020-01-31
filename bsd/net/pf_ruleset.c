/*
 * Copyright (c) 2007-2016 Apple Inc. All rights reserved.
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

/*	$apfw: pf_ruleset.c,v 1.2 2007/08/10 03:00:16 jhw Exp $ */
/*	$OpenBSD: pf_ruleset.c,v 1.1 2006/10/27 13:56:51 mcbride Exp $ */

/*
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002,2003 Henning Brauer
 * NAT64 - Copyright (c) 2010 Viagenie Inc. (http://www.viagenie.ca)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 */

#include <sys/param.h>
#include <sys/socket.h>
#ifdef KERNEL
#include <sys/systm.h>
#include <sys/malloc.h>
#include <libkern/libkern.h>
#endif /* KERNEL */
#include <sys/mbuf.h>

#include <netinet/ip_dummynet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <net/if.h>
#include <net/pfvar.h>

#if INET6
#include <netinet/ip6.h>
#endif /* INET6 */


#ifdef KERNEL
#define DPFPRINTF(format, x ...)         \
	if (pf_status.debug >= PF_DEBUG_NOISY)  \
	        printf(format, ##x)
#define rs_malloc(x)            _MALLOC(x, M_TEMP, M_WAITOK)
#define rs_free(x)              _FREE(x, M_TEMP)
#define strrchr                 _strrchr

static char *
_strrchr(const char *c, int ch)
{
	char *p = (char *)(size_t)c, *save;

	for (save = NULL;; ++p) {
		if (*p == ch) {
			save = (char *)p;
		}
		if (*p == '\0') {
			return save;
		}
	}
	/* NOTREACHED */
}

#else
/* Userland equivalents so we can lend code to pfctl et al. */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define rs_malloc(x)             malloc(x)
#define rs_free(x)               free(x)

#ifdef PFDEBUG
#include <sys/stdarg.h>
#define DPFPRINTF(format, x...) fprintf(stderr, format, ##x)
#else
#define DPFPRINTF(format, x...) ((void)0)
#endif /* PFDEBUG */
#endif /* KERNEL */


struct pf_anchor_global  pf_anchors;
struct pf_anchor         pf_main_anchor;

static __inline int pf_anchor_compare(struct pf_anchor *, struct pf_anchor *);

RB_GENERATE(pf_anchor_global, pf_anchor, entry_global, pf_anchor_compare);
RB_GENERATE(pf_anchor_node, pf_anchor, entry_node, pf_anchor_compare);

static __inline int
pf_anchor_compare(struct pf_anchor *a, struct pf_anchor *b)
{
	int c = strcmp(a->path, b->path);

	return c ? (c < 0 ? -1 : 1) : 0;
}

int
pf_get_ruleset_number(u_int8_t action)
{
	switch (action) {
	case PF_SCRUB:
	case PF_NOSCRUB:
		return PF_RULESET_SCRUB;
	case PF_PASS:
	case PF_DROP:
		return PF_RULESET_FILTER;
	case PF_NAT:
	case PF_NONAT:
		return PF_RULESET_NAT;
	case PF_BINAT:
	case PF_NOBINAT:
		return PF_RULESET_BINAT;
	case PF_RDR:
	case PF_NORDR:
	case PF_NAT64:
	case PF_NONAT64:
		return PF_RULESET_RDR;
#if DUMMYNET
	case PF_DUMMYNET:
	case PF_NODUMMYNET:
		return PF_RULESET_DUMMYNET;
#endif /* DUMMYNET */
	default:
		return PF_RULESET_MAX;
	}
}

void
pf_init_ruleset(struct pf_ruleset *ruleset)
{
	int     i;

	memset(ruleset, 0, sizeof(struct pf_ruleset));
	for (i = 0; i < PF_RULESET_MAX; i++) {
		TAILQ_INIT(&ruleset->rules[i].queues[0]);
		TAILQ_INIT(&ruleset->rules[i].queues[1]);
		ruleset->rules[i].active.ptr = &ruleset->rules[i].queues[0];
		ruleset->rules[i].inactive.ptr = &ruleset->rules[i].queues[1];
	}
}

struct pf_anchor *
pf_find_anchor(const char *path)
{
	struct pf_anchor        *key, *found;

	key = (struct pf_anchor *)rs_malloc(sizeof(*key));
	memset(key, 0, sizeof(*key));
	strlcpy(key->path, path, sizeof(key->path));
	found = RB_FIND(pf_anchor_global, &pf_anchors, key);
	rs_free(key);
	return found;
}

struct pf_ruleset *
pf_find_ruleset(const char *path)
{
	struct pf_anchor        *anchor;

	while (*path == '/') {
		path++;
	}
	if (!*path) {
		return &pf_main_ruleset;
	}
	anchor = pf_find_anchor(path);
	if (anchor == NULL) {
		return NULL;
	} else {
		return &anchor->ruleset;
	}
}

struct pf_ruleset *
pf_find_ruleset_with_owner(const char *path, const char *owner, int is_anchor,
    int *error)
{
	struct pf_anchor        *anchor;

	while (*path == '/') {
		path++;
	}
	if (!*path) {
		return &pf_main_ruleset;
	}
	anchor = pf_find_anchor(path);
	if (anchor == NULL) {
		*error = EINVAL;
		return NULL;
	} else {
		if ((owner && (!strcmp(owner, anchor->owner)))
		    || (is_anchor && !strcmp(anchor->owner, ""))) {
			return &anchor->ruleset;
		}
		*error = EPERM;
		return NULL;
	}
}

struct pf_ruleset *
pf_find_or_create_ruleset(const char *path)
{
	char                    *p, *q = NULL, *r;
	struct pf_ruleset       *ruleset;
	struct pf_anchor        *anchor = 0, *dup, *parent = NULL;

	if (path[0] == 0) {
		return &pf_main_ruleset;
	}
	while (*path == '/') {
		path++;
	}
	ruleset = pf_find_ruleset(path);
	if (ruleset != NULL) {
		return ruleset;
	}
	p = (char *)rs_malloc(MAXPATHLEN);
	bzero(p, MAXPATHLEN);
	strlcpy(p, path, MAXPATHLEN);
	while (parent == NULL && (q = strrchr(p, '/')) != NULL) {
		*q = 0;
		if ((ruleset = pf_find_ruleset(p)) != NULL) {
			parent = ruleset->anchor;
			break;
		}
	}
	if (q == NULL) {
		q = p;
	} else {
		q++;
	}
	strlcpy(p, path, MAXPATHLEN);
	if (!*q) {
		rs_free(p);
		return NULL;
	}
	while ((r = strchr(q, '/')) != NULL || *q) {
		if (r != NULL) {
			*r = 0;
		}
		if (!*q || strlen(q) >= PF_ANCHOR_NAME_SIZE ||
		    (parent != NULL && strlen(parent->path) >=
		    MAXPATHLEN - PF_ANCHOR_NAME_SIZE - 1)) {
			rs_free(p);
			return NULL;
		}
		anchor = (struct pf_anchor *)rs_malloc(sizeof(*anchor));
		if (anchor == NULL) {
			rs_free(p);
			return NULL;
		}
		memset(anchor, 0, sizeof(*anchor));
		RB_INIT(&anchor->children);
		strlcpy(anchor->name, q, sizeof(anchor->name));
		if (parent != NULL) {
			strlcpy(anchor->path, parent->path,
			    sizeof(anchor->path));
			strlcat(anchor->path, "/", sizeof(anchor->path));
		}
		strlcat(anchor->path, anchor->name, sizeof(anchor->path));
		if ((dup = RB_INSERT(pf_anchor_global, &pf_anchors, anchor)) !=
		    NULL) {
			printf("pf_find_or_create_ruleset: RB_INSERT1 "
			    "'%s' '%s' collides with '%s' '%s'\n",
			    anchor->path, anchor->name, dup->path, dup->name);
			rs_free(anchor);
			rs_free(p);
			return NULL;
		}
		if (parent != NULL) {
			anchor->parent = parent;
			if ((dup = RB_INSERT(pf_anchor_node, &parent->children,
			    anchor)) != NULL) {
				printf("pf_find_or_create_ruleset: "
				    "RB_INSERT2 '%s' '%s' collides with "
				    "'%s' '%s'\n", anchor->path, anchor->name,
				    dup->path, dup->name);
				RB_REMOVE(pf_anchor_global, &pf_anchors,
				    anchor);
				rs_free(anchor);
				rs_free(p);
				return NULL;
			}
		}
		pf_init_ruleset(&anchor->ruleset);
		anchor->ruleset.anchor = anchor;
		parent = anchor;
		if (r != NULL) {
			q = r + 1;
		} else {
			*q = 0;
		}
#if DUMMYNET
		if (strncmp("com.apple.nlc", anchor->name,
		    sizeof("com.apple.nlc")) == 0) {
			is_nlc_enabled_glb = TRUE;
		}
#endif
	}
	rs_free(p);
	return anchor ? &anchor->ruleset : 0;
}

void
pf_remove_if_empty_ruleset(struct pf_ruleset *ruleset)
{
	struct pf_anchor        *parent;
	int                      i;

	while (ruleset != NULL) {
		if (ruleset == &pf_main_ruleset || ruleset->anchor == NULL ||
		    !RB_EMPTY(&ruleset->anchor->children) ||
		    ruleset->anchor->refcnt > 0 || ruleset->tables > 0 ||
		    ruleset->topen) {
			return;
		}
		for (i = 0; i < PF_RULESET_MAX; ++i) {
			if (!TAILQ_EMPTY(ruleset->rules[i].active.ptr) ||
			    !TAILQ_EMPTY(ruleset->rules[i].inactive.ptr) ||
			    ruleset->rules[i].inactive.open) {
				return;
			}
		}
		RB_REMOVE(pf_anchor_global, &pf_anchors, ruleset->anchor);
#if DUMMYNET
		if (strncmp("com.apple.nlc", ruleset->anchor->name,
		    sizeof("com.apple.nlc")) == 0) {
			struct dummynet_event dn_event;
			bzero(&dn_event, sizeof(dn_event));
			dn_event.dn_event_code = DUMMYNET_NLC_DISABLED;
			dummynet_event_enqueue_nwk_wq_entry(&dn_event);
			is_nlc_enabled_glb = FALSE;
		}
#endif
		if ((parent = ruleset->anchor->parent) != NULL) {
			RB_REMOVE(pf_anchor_node, &parent->children,
			    ruleset->anchor);
		}
		rs_free(ruleset->anchor);
		if (parent == NULL) {
			return;
		}
		ruleset = &parent->ruleset;
	}
}

int
pf_anchor_setup(struct pf_rule *r, const struct pf_ruleset *s,
    const char *name)
{
	char                    *p, *path;
	struct pf_ruleset       *ruleset;

	r->anchor = NULL;
	r->anchor_relative = 0;
	r->anchor_wildcard = 0;
	if (!name[0]) {
		return 0;
	}
	path = (char *)rs_malloc(MAXPATHLEN);
	bzero(path, MAXPATHLEN);
	if (name[0] == '/') {
		strlcpy(path, name + 1, MAXPATHLEN);
	} else {
		/* relative path */
		r->anchor_relative = 1;
		if (s->anchor == NULL || !s->anchor->path[0]) {
			path[0] = 0;
		} else {
			strlcpy(path, s->anchor->path, MAXPATHLEN);
		}
		while (name[0] == '.' && name[1] == '.' && name[2] == '/') {
			if (!path[0]) {
				printf("pf_anchor_setup: .. beyond root\n");
				rs_free(path);
				return 1;
			}
			if ((p = strrchr(path, '/')) != NULL) {
				*p = 0;
			} else {
				path[0] = 0;
			}
			r->anchor_relative++;
			name += 3;
		}
		if (path[0]) {
			strlcat(path, "/", MAXPATHLEN);
		}
		strlcat(path, name, MAXPATHLEN);
	}
	if ((p = strrchr(path, '/')) != NULL && strcmp(p, "/*") == 0) {
		r->anchor_wildcard = 1;
		*p = 0;
	}
	ruleset = pf_find_or_create_ruleset(path);
	rs_free(path);
	if (ruleset == NULL || ruleset->anchor == NULL) {
		printf("pf_anchor_setup: ruleset\n");
		return 1;
	}
	r->anchor = ruleset->anchor;
	r->anchor->refcnt++;
	return 0;
}

int
pf_anchor_copyout(const struct pf_ruleset *rs, const struct pf_rule *r,
    struct pfioc_rule *pr)
{
	pr->anchor_call[0] = 0;
	if (r->anchor == NULL) {
		return 0;
	}
	if (!r->anchor_relative) {
		strlcpy(pr->anchor_call, "/", sizeof(pr->anchor_call));
		strlcat(pr->anchor_call, r->anchor->path,
		    sizeof(pr->anchor_call));
	} else {
		char    *a, *p;
		int      i;

		a = (char *)rs_malloc(MAXPATHLEN);
		bzero(a, MAXPATHLEN);
		if (rs->anchor == NULL) {
			a[0] = 0;
		} else {
			strlcpy(a, rs->anchor->path, MAXPATHLEN);
		}
		for (i = 1; i < r->anchor_relative; ++i) {
			if ((p = strrchr(a, '/')) == NULL) {
				p = a;
			}
			*p = 0;
			strlcat(pr->anchor_call, "../",
			    sizeof(pr->anchor_call));
		}
		if (strncmp(a, r->anchor->path, strlen(a))) {
			printf("pf_anchor_copyout: '%s' '%s'\n", a,
			    r->anchor->path);
			rs_free(a);
			return 1;
		}
		if (strlen(r->anchor->path) > strlen(a)) {
			strlcat(pr->anchor_call, r->anchor->path + (a[0] ?
			    strlen(a) + 1 : 0), sizeof(pr->anchor_call));
		}
		rs_free(a);
	}
	if (r->anchor_wildcard) {
		strlcat(pr->anchor_call, pr->anchor_call[0] ? "/*" : "*",
		    sizeof(pr->anchor_call));
	}
	return 0;
}

void
pf_anchor_remove(struct pf_rule *r)
{
	if (r->anchor == NULL) {
		return;
	}
	if (r->anchor->refcnt <= 0) {
		printf("pf_anchor_remove: broken refcount\n");
		r->anchor = NULL;
		return;
	}
	if (!--r->anchor->refcnt) {
		pf_remove_if_empty_ruleset(&r->anchor->ruleset);
	}
	r->anchor = NULL;
}
