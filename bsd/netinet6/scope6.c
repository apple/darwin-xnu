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

#include <net/route.h>
#include <net/if.h>

#include <netinet/in.h>

#include <netinet6/in6_var.h>
#include <netinet6/scope6_var.h>

struct scope6_id {
	/*
	 * 16 is correspondent to 4bit multicast scope field.
	 * i.e. from node-local to global with some reserved/unassigned types.
	 */
	u_int32_t s6id_list[16];
};
static size_t if_indexlim = 8;
struct scope6_id *scope6_ids = NULL;

void
scope6_ifattach(
	struct ifnet *ifp)
{
	/*
	 * We have some arrays that should be indexed by if_index.
	 * since if_index will grow dynamically, they should grow too.
	 */
	if (scope6_ids == NULL || if_index >= if_indexlim) {
		size_t n;
		caddr_t q;

		while (if_index >= if_indexlim)
			if_indexlim <<= 1;

		/* grow scope index array */
		n = if_indexlim * sizeof(struct scope6_id);
		/* XXX: need new malloc type? */
		q = (caddr_t)_MALLOC(n, M_IFADDR, M_WAITOK);
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
		return;
	}

	/*
	 * XXX: IPV6_ADDR_SCOPE_xxx macros are not standard.
	 * Should we rather hardcode here?
	 */
	SID.s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL] = ifp->if_index;
#if MULTI_SCOPE
	/* by default, we don't care about scope boundary for these scopes. */
	SID.s6id_list[IPV6_ADDR_SCOPE_SITELOCAL] = 1;
	SID.s6id_list[IPV6_ADDR_SCOPE_ORGLOCAL] = 1;
#endif
#undef SID
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

	for (i = 0; i < 16; i++) {
		if (idlist[i] &&
		    idlist[i] != scope6_ids[ifp->if_index].s6id_list[i]) {
			if (i == IPV6_ADDR_SCOPE_LINKLOCAL &&
			    idlist[i] > if_index) {
				/*
				 * XXX: theoretically, there should be no
				 * relationship between link IDs and interface
				 * IDs, but we check the consistency for
				 * safety in later use.
				 */
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

	return(error);
}

int
scope6_get(
	struct ifnet *ifp,
	u_int32_t *idlist)
{
	if (scope6_ids == NULL)	/* paranoid? */
		return(EINVAL);

	bcopy(scope6_ids[ifp->if_index].s6id_list, idlist,
	      sizeof(scope6_ids[ifp->if_index].s6id_list));

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
		case IPV6_ADDR_SCOPE_NODELOCAL:
			return IPV6_ADDR_SCOPE_NODELOCAL;
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

	if (bcmp(&in6addr_loopback, addr, sizeof(*addr) - 1) == 0) {
		if (addr->s6_addr8[15] == 1) /* loopback */
			return IPV6_ADDR_SCOPE_NODELOCAL;
		if (addr->s6_addr8[15] == 0) /* unspecified */
			return IPV6_ADDR_SCOPE_LINKLOCAL;
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

	if (scope6_ids == NULL)	/* paranoid? */
		return(0);	/* XXX */
	if (index >= if_indexlim)
		return(0);	/* XXX */

#define SID scope6_ids[index]
	switch(scope) {
	case IPV6_ADDR_SCOPE_NODELOCAL:
		return(-1);	/* XXX: is this an appropriate value? */

	case IPV6_ADDR_SCOPE_LINKLOCAL:
		return(SID.s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL]);

	case IPV6_ADDR_SCOPE_SITELOCAL:
		return(SID.s6id_list[IPV6_ADDR_SCOPE_SITELOCAL]);

	case IPV6_ADDR_SCOPE_ORGLOCAL:
		return(SID.s6id_list[IPV6_ADDR_SCOPE_ORGLOCAL]);

	default:
		return(0);	/* XXX: treat as global. */
	}
#undef SID
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
	if (ifp) {
		scope6_ids[0].s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL] =
			ifp->if_index;
	}
	else
		scope6_ids[0].s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL] = 0;
}

int
scope6_get_default(
	u_int32_t *idlist)
{
	if (scope6_ids == NULL)	/* paranoid? */
		return(EINVAL);

	bcopy(scope6_ids[0].s6id_list, idlist,
	      sizeof(scope6_ids[0].s6id_list));

	return(0);
}

u_int32_t
scope6_addr2default(
	struct in6_addr *addr)
{
	return(scope6_ids[0].s6id_list[in6_addrscope(addr)]);
}
