/*
 * Copyright (c) 2009-2013 Apple Inc. All rights reserved.
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

#ifdef ENABLE_DEFAULT_SCOPE
int ip6_use_defzone = 1;
#else
int ip6_use_defzone = 0;
#endif

decl_lck_mtx_data(static, scope6_lock);
static struct scope6_id sid_default;

#define SID(ifp) &IN6_IFEXTRA(ifp)->scope6_id

void
scope6_init(lck_grp_t *grp, lck_attr_t *attr)
{
	bzero(&sid_default, sizeof(sid_default));
	lck_mtx_init(&scope6_lock, grp, attr);
}

void
scope6_ifattach(struct ifnet *ifp)
{
	struct scope6_id *sid;

	VERIFY(IN6_IFEXTRA(ifp) != NULL);
	if_inet6data_lock_exclusive(ifp);
	sid = SID(ifp);
	/* N.B.: the structure is already zero'ed */
	/*
	 * XXX: IPV6_ADDR_SCOPE_xxx macros are not standard.
	 * Should we rather hardcode here?
	 */
	sid->s6id_list[IPV6_ADDR_SCOPE_INTFACELOCAL] = ifp->if_index;
	sid->s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL] = ifp->if_index;
#if MULTI_SCOPE
	/* by default, we don't care about scope boundary for these scopes. */
	sid->s6id_list[IPV6_ADDR_SCOPE_SITELOCAL] = 1;
	sid->s6id_list[IPV6_ADDR_SCOPE_ORGLOCAL] = 1;
#endif
	if_inet6data_lock_done(ifp);
}

/*
 * Get a scope of the address. Node-local, link-local, site-local or global.
 */
int
in6_addrscope(struct in6_addr *addr)
{
	int scope;

	if (addr->s6_addr8[0] == 0xfe) {
		scope = addr->s6_addr8[1] & 0xc0;

		switch (scope) {
		case 0x80:
			return IPV6_ADDR_SCOPE_LINKLOCAL;
		case 0xc0:
			return IPV6_ADDR_SCOPE_SITELOCAL;
		default:
			return IPV6_ADDR_SCOPE_GLOBAL; /* just in case */
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
		case IPV6_ADDR_SCOPE_LINKLOCAL:
			return IPV6_ADDR_SCOPE_LINKLOCAL;
		case IPV6_ADDR_SCOPE_SITELOCAL:
			return IPV6_ADDR_SCOPE_SITELOCAL;
		default:
			return IPV6_ADDR_SCOPE_GLOBAL;
		}
	}

	/*
	 * Regard loopback and unspecified addresses as global, since
	 * they have no ambiguity.
	 */
	if (bcmp(&in6addr_loopback, addr, sizeof(*addr) - 1) == 0) {
		if (addr->s6_addr8[15] == 1) { /* loopback */
			return IPV6_ADDR_SCOPE_LINKLOCAL;
		}
		if (addr->s6_addr8[15] == 0) { /* unspecified */
			return IPV6_ADDR_SCOPE_GLOBAL; /* XXX: correct? */
		}
	}

	return IPV6_ADDR_SCOPE_GLOBAL;
}

int
in6_addr2scopeid(struct ifnet *ifp, struct in6_addr *addr)
{
	int scope = in6_addrscope(addr);
	int retid = 0;
	struct scope6_id *sid;

	if_inet6data_lock_shared(ifp);
	if (IN6_IFEXTRA(ifp) == NULL) {
		goto err;
	}
	sid = SID(ifp);
	switch (scope) {
	case IPV6_ADDR_SCOPE_NODELOCAL:
		retid = -1;     /* XXX: is this an appropriate value? */
		break;
	case IPV6_ADDR_SCOPE_LINKLOCAL:
		retid = sid->s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL];
		break;
	case IPV6_ADDR_SCOPE_SITELOCAL:
		retid = sid->s6id_list[IPV6_ADDR_SCOPE_SITELOCAL];
		break;
	case IPV6_ADDR_SCOPE_ORGLOCAL:
		retid = sid->s6id_list[IPV6_ADDR_SCOPE_ORGLOCAL];
		break;
	default:
		break;  /* XXX: value 0, treat as global. */
	}
err:
	if_inet6data_lock_done(ifp);

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

	if ((zoneid = sin6->sin6_scope_id) == 0 && defaultok) {
		zoneid = scope6_addr2default(&sin6->sin6_addr);
	}

	if (zoneid != 0 &&
	    (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(&sin6->sin6_addr))) {
		/*
		 * At this moment, we only check interface-local and
		 * link-local scope IDs, and use interface indices as the
		 * zone IDs assuming a one-to-one mapping between interfaces
		 * and links.
		 */
		if (if_index < zoneid) {
			return ENXIO;
		}
		ifnet_head_lock_shared();
		ifp = ifindex2ifnet[zoneid];
		if (ifp == NULL) {      /* XXX: this can happen for some OS */
			ifnet_head_done();
			return ENXIO;
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

	*sin6 = *((struct sockaddr_in6 *)(void *)rt_key(rt));
	sin6->sin6_scope_id = 0;
}

void
rtgw_to_sa6(struct rtentry *rt, struct sockaddr_in6 *sin6)
{
	VERIFY(rt->rt_flags & RTF_GATEWAY);

	*sin6 = *((struct sockaddr_in6 *)(void *)rt->rt_gateway);
	sin6->sin6_scope_id = 0;
}

/*
 * generate standard sockaddr_in6 from embedded form.
 */
int
sa6_recoverscope(struct sockaddr_in6 *sin6, boolean_t attachcheck)
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
			if (if_index < zoneid) {
				return ENXIO;
			}
			/*
			 * We use the attachcheck parameter to skip the
			 * interface attachment check.
			 * Some callers might hold the ifnet_head lock in
			 * exclusive mode. This means that:
			 * 1) the interface can't go away -- hence we don't
			 *    need to perform this check
			 * 2) we can't perform this check because the lock is
			 *    in exclusive mode and trying to lock it in shared
			 *    mode would cause a deadlock.
			 */
			if (attachcheck) {
				ifnet_head_lock_shared();
				if (ifindex2ifnet[zoneid] == NULL) {
					ifnet_head_done();
					return ENXIO;
				}
				ifnet_head_done();
			}
			sin6->sin6_addr.s6_addr16[1] = 0;
			sin6->sin6_scope_id = zoneid;
		}
	}

	return 0;
}

void
scope6_setdefault(struct ifnet *ifp)
{
	/*
	 * Currently, this function just set the default "link" according to
	 * the given interface.
	 * We might eventually have to separate the notion of "link" from
	 * "interface" and provide a user interface to set the default.
	 */
	lck_mtx_lock(&scope6_lock);
	if (ifp != NULL) {
		sid_default.s6id_list[IPV6_ADDR_SCOPE_INTFACELOCAL] =
		    ifp->if_index;
		sid_default.s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL] =
		    ifp->if_index;
	} else {
		sid_default.s6id_list[IPV6_ADDR_SCOPE_INTFACELOCAL] = 0;
		sid_default.s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL] = 0;
	}
	lck_mtx_unlock(&scope6_lock);
}


u_int32_t
scope6_addr2default(struct in6_addr *addr)
{
	u_int32_t id = 0;
	int index = in6_addrscope(addr);

	/*
	 * special case: The loopback address should be considered as
	 * link-local, but there's no ambiguity in the syntax.
	 */
	if (IN6_IS_ADDR_LOOPBACK(addr)) {
		return 0;
	}

	lck_mtx_lock(&scope6_lock);
	id = sid_default.s6id_list[index];
	lck_mtx_unlock(&scope6_lock);

	return id;
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
	struct scope6_id *sid;

	/*
	 * special case: the loopback address can only belong to a loopback
	 * interface.
	 */
	if (IN6_IS_ADDR_LOOPBACK(in6)) {
		if (!(ifp->if_flags & IFF_LOOPBACK)) {
			return EINVAL;
		} else {
			if (ret_id != NULL) {
				*ret_id = 0; /* there's no ambiguity */
			}
			return 0;
		}
	}

	scope = in6_addrscope(in6);

	if_inet6data_lock_shared(ifp);
	if (IN6_IFEXTRA(ifp) == NULL) {
		if_inet6data_lock_done(ifp);
		if (ret_id) {
			*ret_id = 0;
		}
		return EINVAL;
	}
	sid = SID(ifp);
	switch (scope) {
	case IPV6_ADDR_SCOPE_INTFACELOCAL: /* should be interface index */
		zoneid = sid->s6id_list[IPV6_ADDR_SCOPE_INTFACELOCAL];
		break;

	case IPV6_ADDR_SCOPE_LINKLOCAL:
		zoneid = sid->s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL];
		break;

	case IPV6_ADDR_SCOPE_SITELOCAL:
		zoneid = sid->s6id_list[IPV6_ADDR_SCOPE_SITELOCAL];
		break;

	case IPV6_ADDR_SCOPE_ORGLOCAL:
		zoneid = sid->s6id_list[IPV6_ADDR_SCOPE_ORGLOCAL];
		break;
	default:
		zoneid = 0;     /* XXX: treat as global. */
		break;
	}
	if_inet6data_lock_done(ifp);

	if (ret_id != NULL) {
		*ret_id = zoneid;
	}

	if (IN6_IS_SCOPE_LINKLOCAL(in6) || IN6_IS_ADDR_MC_INTFACELOCAL(in6)) {
		in6->s6_addr16[1] = htons(zoneid & 0xffff); /* XXX */
	}
	return 0;
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
		if (in6->s6_addr16[1] != 0) {
			modified = 1;
		}
		in6->s6_addr16[1] = 0;
	}

	return modified;
}
