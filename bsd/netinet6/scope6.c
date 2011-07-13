/*
 * Copyright (c) 2009-2010 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/scope6.c,v 1.3 2002/03/25 10:12:51 ume Exp $	*/
/*	$KAME: scope6.c,v 1.10 2000/07/24 13:29:31 itojun Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/syslog.h>
#include <sys/mcache.h>

#include <net/route.h>
#include <net/if.h>

#include <netinet/in.h>

#include <netinet6/in6_var.h>
#include <netinet6/scope6_var.h>

extern lck_mtx_t *scope6_mutex;

#ifdef ENABLE_DEFAULT_SCOPE
int ip6_use_defzone = 1;
#else
int ip6_use_defzone = 0;
#endif

static size_t if_scope_indexlim = 8;
struct scope6_id *scope6_ids = NULL;

int
scope6_ifattach(
	struct ifnet *ifp)
{
	/*
	 * We have some arrays that should be indexed by if_index.
	 * since if_index will grow dynamically, they should grow too.
	 */
	lck_mtx_lock(scope6_mutex);
	if (scope6_ids == NULL || if_index >= if_scope_indexlim) {
		size_t n;
		caddr_t q;
		int newlim = if_scope_indexlim;

		while (if_index >= newlim)
			newlim <<= 1;

		/* grow scope index array */
		n = newlim * sizeof(struct scope6_id);
		/* XXX: need new malloc type? */
		q = (caddr_t)_MALLOC(n, M_IFADDR, M_WAITOK);
		if (q == NULL) {
			lck_mtx_unlock(scope6_mutex);
			return ENOBUFS;
		}
		if_scope_indexlim = newlim;
		bzero(q, n);
		if (scope6_ids) {
			bcopy((caddr_t)scope6_ids, q, n/2);
			FREE((caddr_t)scope6_ids, M_IFADDR);
		}
		scope6_ids = (struct scope6_id *)q;
	}

#define SID scope6_ids[ifp->if_index]

	/* don't initialize if called twice */
	if (SID.s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL]) {
		lck_mtx_unlock(scope6_mutex);
		return 0;
	}

	/*
	 * XXX: IPV6_ADDR_SCOPE_xxx macros are not standard.
	 * Should we rather hardcode here?
	 */
	SID.s6id_list[IPV6_ADDR_SCOPE_INTFACELOCAL] = ifp->if_index;
	SID.s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL] = ifp->if_index;
#if MULTI_SCOPE
	/* by default, we don't care about scope boundary for these scopes. */
	SID.s6id_list[IPV6_ADDR_SCOPE_SITELOCAL] = 1;
	SID.s6id_list[IPV6_ADDR_SCOPE_ORGLOCAL] = 1;
#endif
#undef SID
	lck_mtx_unlock(scope6_mutex);

	return 0;
}

int
scope6_set(
	struct ifnet *ifp,
	u_int32_t *idlist)
{
	int i;
	int error = 0;

	if (scope6_ids == NULL)	/* paranoid? */
		return(EINVAL);

	/*
	 * XXX: We need more consistency checks of the relationship among
	 * scopes (e.g. an organization should be larger than a site).
	 */

	/*
	 * TODO(XXX): after setting, we should reflect the changes to
	 * interface addresses, routing table entries, PCB entries...
	 */

	lck_mtx_lock(scope6_mutex);
	for (i = 0; i < 16; i++) {
		if (idlist[i] &&
		    idlist[i] != scope6_ids[ifp->if_index].s6id_list[i]) {
			if (i == IPV6_ADDR_SCOPE_INTFACELOCAL &&
			    idlist[i] > if_index) {
				/*
				 * XXX: theoretically, there should be no
				 * relationship between link IDs and interface
				 * IDs, but we check the consistency for
				 * safety in later use.
				 */
				lck_mtx_unlock(scope6_mutex);
				return(EINVAL);
			}

			/*
			 * XXX: we must need lots of work in this case,
			 * but we simply set the new value in this initial
			 * implementation.
			 */
			scope6_ids[ifp->if_index].s6id_list[i] = idlist[i];
		}
	}
	lck_mtx_unlock(scope6_mutex);

	return(error);
}

int
scope6_get(
	struct ifnet *ifp,
	u_int32_t *idlist)
{
	if (scope6_ids == NULL)	/* paranoid? */
		return(EINVAL);

	lck_mtx_lock(scope6_mutex);
	bcopy(scope6_ids[ifp->if_index].s6id_list, idlist,
	      sizeof(scope6_ids[ifp->if_index].s6id_list));
	lck_mtx_unlock(scope6_mutex);

	return(0);
}


/*
 * Get a scope of the address. Node-local, link-local, site-local or global.
 */
int
in6_addrscope(addr)
struct in6_addr *addr;
{
	int scope;

	if (addr->s6_addr8[0] == 0xfe) {
		scope = addr->s6_addr8[1] & 0xc0;

		switch (scope) {
		case 0x80:
			return IPV6_ADDR_SCOPE_LINKLOCAL;
			break;
		case 0xc0:
			return IPV6_ADDR_SCOPE_SITELOCAL;
			break;
		default:
			return IPV6_ADDR_SCOPE_GLOBAL; /* just in case */
			break;
		}
	}


	if (addr->s6_addr8[0] == 0xff) {
		scope = addr->s6_addr8[1] & 0x0f;

		/*
		 * due to other scope such as reserved,
		 * return scope doesn't work.
		 */
		switch (scope) {
		case IPV6_ADDR_SCOPE_INTFACELOCAL:
			return IPV6_ADDR_SCOPE_INTFACELOCAL;
			break;
		case IPV6_ADDR_SCOPE_LINKLOCAL:
			return IPV6_ADDR_SCOPE_LINKLOCAL;
			break;
		case IPV6_ADDR_SCOPE_SITELOCAL:
			return IPV6_ADDR_SCOPE_SITELOCAL;
			break;
		default:
			return IPV6_ADDR_SCOPE_GLOBAL;
			break;
		}
	}

	/*
	 * Regard loopback and unspecified addresses as global, since
	 * they have no ambiguity.
	 */
	if (bcmp(&in6addr_loopback, addr, sizeof(*addr) - 1) == 0) {
		if (addr->s6_addr8[15] == 1) /* loopback */
			return IPV6_ADDR_SCOPE_LINKLOCAL;
		if (addr->s6_addr8[15] == 0) /* unspecified */
			return IPV6_ADDR_SCOPE_GLOBAL; /* XXX: correct? */
	}

	return IPV6_ADDR_SCOPE_GLOBAL;
}

int
in6_addr2scopeid(
	struct ifnet *ifp,	/* must not be NULL */
	struct in6_addr *addr)	/* must not be NULL */
{
	int scope = in6_addrscope(addr);
	int index = ifp->if_index;
	int retid = 0;

	if (scope6_ids == NULL)	/* paranoid? */
		return(0);	/* XXX */
	
	lck_mtx_lock(scope6_mutex);
	if (index >= if_scope_indexlim) {
		lck_mtx_unlock(scope6_mutex);
		return(0);	/* XXX */
	}

#define SID scope6_ids[index]
	switch(scope) {
	case IPV6_ADDR_SCOPE_NODELOCAL:
		retid = -1;	/* XXX: is this an appropriate value? */
		break;
	case IPV6_ADDR_SCOPE_LINKLOCAL:
		retid=SID.s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL];
		break;
	case IPV6_ADDR_SCOPE_SITELOCAL:
		retid=SID.s6id_list[IPV6_ADDR_SCOPE_SITELOCAL];
		break;
	case IPV6_ADDR_SCOPE_ORGLOCAL:
		retid=SID.s6id_list[IPV6_ADDR_SCOPE_ORGLOCAL];
		break;
	default:
		break;	/* XXX: value 0, treat as global. */
	}
#undef SID

	lck_mtx_unlock(scope6_mutex);
	return retid;
}

/*
 * Validate the specified scope zone ID in the sin6_scope_id field.  If the ID
 * is unspecified (=0), needs to be specified, and the default zone ID can be
 * used, the default value will be used.
 * This routine then generates the kernel-internal form: if the address scope
 * of is interface-local or link-local, embed the interface index in the
 * address.
 */
int
sa6_embedscope(struct sockaddr_in6 *sin6, int defaultok)
{
	struct ifnet *ifp;
	u_int32_t zoneid;

	if ((zoneid = sin6->sin6_scope_id) == 0 && defaultok)
		zoneid = scope6_addr2default(&sin6->sin6_addr);

	if (zoneid != 0 &&
	    (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(&sin6->sin6_addr))) {
		/*
		 * At this moment, we only check interface-local and
		 * link-local scope IDs, and use interface indices as the
		 * zone IDs assuming a one-to-one mapping between interfaces
		 * and links.
		 */
		if (if_index < zoneid)
			return (ENXIO);
		ifnet_head_lock_shared();
		ifp = ifindex2ifnet[zoneid];
		if (ifp == NULL) {/* XXX: this can happen for some OS */
			ifnet_head_done();
			return (ENXIO);
		}
		ifnet_head_done();
		/* XXX assignment to 16bit from 32bit variable */
		sin6->sin6_addr.s6_addr16[1] = htons(zoneid & 0xffff);

		sin6->sin6_scope_id = 0;
	}

	return 0;
}

void
rtkey_to_sa6(struct rtentry *rt, struct sockaddr_in6 *sin6)
{
	VERIFY(rt_key(rt)->sa_family == AF_INET6);

	*sin6 = *((struct sockaddr_in6 *)rt_key(rt));
	sin6->sin6_scope_id = 0;
}

void
rtgw_to_sa6(struct rtentry *rt, struct sockaddr_in6 *sin6)
{
	VERIFY(rt->rt_flags & RTF_GATEWAY);

	*sin6 = *((struct sockaddr_in6 *)rt->rt_gateway);
	sin6->sin6_scope_id = 0;
}

/*
 * generate standard sockaddr_in6 from embedded form.
 */
int
sa6_recoverscope(struct sockaddr_in6 *sin6)
{
	u_int32_t zoneid;

	if (sin6->sin6_scope_id != 0) {
		log(LOG_NOTICE,
		    "sa6_recoverscope: assumption failure (non 0 ID): %s%%%d\n",
		    ip6_sprintf(&sin6->sin6_addr), sin6->sin6_scope_id);
		/* XXX: proceed anyway... */
	}
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(&sin6->sin6_addr)) {
		/*
		 * KAME assumption: link id == interface id
		 */
		zoneid = ntohs(sin6->sin6_addr.s6_addr16[1]);
		if (zoneid) {
			/* sanity check */
			if (if_index < zoneid)
				return (ENXIO);
			ifnet_head_lock_shared();
			if (ifindex2ifnet[zoneid] == NULL) {
				ifnet_head_done();
				return (ENXIO);
			}
			ifnet_head_done();
			sin6->sin6_addr.s6_addr16[1] = 0;
			sin6->sin6_scope_id = zoneid;
		}
	}

	return 0;
}

void
scope6_setdefault(
	struct ifnet *ifp)	/* note that this might be NULL */
{
	/*
	 * Currently, this function just set the default "link" according to
	 * the given interface.
	 * We might eventually have to separate the notion of "link" from
	 * "interface" and provide a user interface to set the default.
	 */
	lck_mtx_lock(scope6_mutex);
	if (ifp) {
		scope6_ids[0].s6id_list[IPV6_ADDR_SCOPE_INTFACELOCAL] =
			ifp->if_index;
		scope6_ids[0].s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL] =
			ifp->if_index;
	} else {
		scope6_ids[0].s6id_list[IPV6_ADDR_SCOPE_INTFACELOCAL] = 0;
		scope6_ids[0].s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL] = 0;
	}
	lck_mtx_unlock(scope6_mutex);
}

int
scope6_get_default(
	u_int32_t *idlist)
{
	if (scope6_ids == NULL)	/* paranoid? */
		return(EINVAL);

	lck_mtx_lock(scope6_mutex);
	bcopy(scope6_ids[0].s6id_list, idlist,
	      sizeof(scope6_ids[0].s6id_list));
	lck_mtx_unlock(scope6_mutex);

	return(0);
}

u_int32_t
scope6_addr2default(
	struct in6_addr *addr)
{
	u_int32_t id = 0;
	int index = in6_addrscope(addr);
	lck_mtx_lock(scope6_mutex);
	id = scope6_ids[0].s6id_list[index];
	lck_mtx_unlock(scope6_mutex);
	return (id);
}

/*
 * Determine the appropriate scope zone ID for in6 and ifp.  If ret_id is
 * non NULL, it is set to the zone ID.  If the zone ID needs to be embedded
 * in the in6_addr structure, in6 will be modified.
 *
 * ret_id - unnecessary?
 */
int
in6_setscope(struct in6_addr *in6, struct ifnet *ifp, u_int32_t *ret_id)
{
	int scope;
	u_int32_t zoneid = 0;
	int index = ifp->if_index;

#ifdef DIAGNOSTIC
	if (scope6_ids == NULL) { /* should not happen */
		panic("in6_setscope: scope array is NULL");
		/* NOTREACHED */
	}
#endif

	/*
	 * special case: the loopback address can only belong to a loopback
	 * interface.
	 */
	if (IN6_IS_ADDR_LOOPBACK(in6)) {
		if (!(ifp->if_flags & IFF_LOOPBACK)) {
			return (EINVAL);
		} else {
			if (ret_id != NULL)
				*ret_id = 0; /* there's no ambiguity */
			return (0);
		}
	}

	scope = in6_addrscope(in6);

#define SID scope6_ids[index]
	lck_mtx_lock(scope6_mutex);
	switch (scope) {
	case IPV6_ADDR_SCOPE_INTFACELOCAL: /* should be interface index */
		zoneid = SID.s6id_list[IPV6_ADDR_SCOPE_INTFACELOCAL];
		break;

	case IPV6_ADDR_SCOPE_LINKLOCAL:
		zoneid = SID.s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL];
		break;

	case IPV6_ADDR_SCOPE_SITELOCAL:
		zoneid = SID.s6id_list[IPV6_ADDR_SCOPE_SITELOCAL];
		break;

	case IPV6_ADDR_SCOPE_ORGLOCAL:
		zoneid = SID.s6id_list[IPV6_ADDR_SCOPE_ORGLOCAL];
		break;
#undef SID
	default:
		zoneid = 0;	/* XXX: treat as global. */
		break;
	}
	lck_mtx_unlock(scope6_mutex);

	if (ret_id != NULL)
		*ret_id = zoneid;

	if (IN6_IS_SCOPE_LINKLOCAL(in6) || IN6_IS_ADDR_MC_INTFACELOCAL(in6))
		in6->s6_addr16[1] = htons(zoneid & 0xffff); /* XXX */

	return (0);
}

/*
 * Just clear the embedded scope identifier.  Return 0 if the original address
 * is intact; return non 0 if the address is modified.
 */
int
in6_clearscope(struct in6_addr *in6)
{
	int modified = 0;

	if (IN6_IS_SCOPE_LINKLOCAL(in6) || IN6_IS_ADDR_MC_INTFACELOCAL(in6)) {
		if (in6->s6_addr16[1] != 0)
			modified = 1;
		in6->s6_addr16[1] = 0;
	}

	return (modified);
}

