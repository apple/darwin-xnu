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
/* Copyright (c) 1998, 1999 Apple Computer, Inc. All Rights Reserved */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)uipc_domain.c	8.3 (Berkeley) 2/14/95
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/queue.h>

void	pffasttimo(void *);
void	pfslowtimo(void *);

/*
 * Add/delete 'domain': Link structure into system list,
 *  invoke the domain init, and then the proto inits.
 * To delete, just remove from the list (dom_refs must be zero)
 */

lck_grp_t		*domain_proto_mtx_grp;
lck_attr_t	*domain_proto_mtx_attr;
static lck_grp_attr_t	*domain_proto_mtx_grp_attr;
lck_mtx_t		*domain_proto_mtx;
extern int		do_reclaim;

void init_domain(register struct domain *dp)
{
	struct protosw  *pr;
	
	if ((dp->dom_mtx = lck_mtx_alloc_init(domain_proto_mtx_grp, domain_proto_mtx_attr)) == NULL) {
		printf("init_domain: can't init domain mtx for domain=%s\n", dp->dom_name);
		return;	/* we have a problem... */
	}

	if (dp->dom_init)
		(*dp->dom_init)();

	/* and then init the currently installed protos in this domain */

	for (pr = dp->dom_protosw; pr; pr = pr->pr_next) {
		if (pr->pr_usrreqs == 0)
			panic("domaininit: %ssw[%d] has no usrreqs!",
			      dp->dom_name, 
			      (int)(pr - dp->dom_protosw));

		if (pr->pr_init)
			(*pr->pr_init)();
	}

	/* Recompute for new protocol */
	if (max_linkhdr < 16)		/* XXX - Sheesh; everything's ether? */
		max_linkhdr = 16;
	if (dp->dom_protohdrlen > max_protohdr)
		max_protohdr = dp->dom_protohdrlen;
	max_hdr = max_linkhdr + max_protohdr;
	max_datalen = MHLEN - max_hdr;
}

void	concat_domain(struct domain *dp) 
{
	lck_mtx_assert(domain_proto_mtx, LCK_MTX_ASSERT_OWNED);
	dp->dom_next = domains; 
	domains = dp; 
}

void
net_add_domain(register struct domain *dp)
{	register struct protosw *pr;

	kprintf("Adding domain %s (family %d)\n", dp->dom_name,
		dp->dom_family);
	/* First, link in the domain */

	lck_mtx_lock(domain_proto_mtx);
	concat_domain(dp);

	init_domain(dp);
	lck_mtx_unlock(domain_proto_mtx);

}

int
net_del_domain(register struct domain *dp)
{	register struct domain *dp1, *dp2;
	register int retval = 0;

	lck_mtx_lock(domain_proto_mtx);
 
	if (dp->dom_refs) {
		lck_mtx_unlock(domain_proto_mtx);
		return(EBUSY);
     }

	for (dp2 = NULL, dp1 = domains; dp1; dp2 = dp1, dp1 = dp1->dom_next)
	{	if (dp == dp1)
			break;
	}
	if (dp1)
	{	if (dp2)
			dp2->dom_next = dp1->dom_next;
		else
			domains = dp1->dom_next;
	} else
		retval = EPFNOSUPPORT;
	lck_mtx_unlock(domain_proto_mtx);

	return(retval);
}

/*
 * net_add_proto - link a protosw into a domain's protosw chain
 * 
 * note: protocols must use their own domain lock before calling net_add_proto
 */
int
net_add_proto(register struct protosw *pp,
	      register struct domain *dp)
{	register struct protosw *pp1, *pp2;

	for (pp2 = NULL, pp1 = dp->dom_protosw; pp1; pp1 = pp1->pr_next)
	{	if (pp1->pr_type == pp->pr_type &&
		    pp1->pr_protocol == pp->pr_protocol) {
			return(EEXIST);
		}
		pp2 = pp1;
	}
	if (pp2 == NULL)
		dp->dom_protosw = pp;
	else
		pp2->pr_next = pp;
	pp->pr_next = NULL;
	TAILQ_INIT(&pp->pr_filter_head);
	if (pp->pr_init)
		(*pp->pr_init)();

	/* Make sure pr_init isn't called again!! */
	pp->pr_init = 0;
	return(0);
}

/*
 * net_del_proto - remove a protosw from a domain's protosw chain.
 * Search the protosw chain for the element with matching data.
 * Then unlink and return.
 *
 * note: protocols must use their own domain lock before calling net_del_proto
 */
int
net_del_proto(register int type,
	      register int protocol,
	      register struct domain *dp)
{	register struct protosw *pp1, *pp2;

	for (pp2 = NULL, pp1 = dp->dom_protosw; pp1; pp1 = pp1->pr_next)
	{	if (pp1->pr_type == type &&
		    pp1->pr_protocol == protocol)
			break;
		pp2 = pp1;
	}
        if (pp1 == NULL) {
			return(ENXIO);
		}
	if (pp2)
		pp2->pr_next = pp1->pr_next;
	else
		dp->dom_protosw = pp1->pr_next;
	return(0);
}


void
domaininit()
{	register struct domain *dp;
	register struct protosw *pr;
	extern struct domain localdomain, routedomain, ndrvdomain, inetdomain;
	extern struct domain systemdomain;
#if NS
	extern struct domain nsdomain;
#endif
#if ISO
	extern struct domain isodomain;
#endif
#if CCITT
	extern struct domain ccittdomain;
#endif

#if NETAT
	extern struct domain atalkdomain;
#endif
#if INET6
	extern struct domain inet6domain;
#endif
#if IPSEC
	extern struct domain keydomain;
#endif

	/*
	 * allocate lock group attribute and group for domain mutexes
	 */
	domain_proto_mtx_grp_attr = lck_grp_attr_alloc_init();

	domain_proto_mtx_grp = lck_grp_alloc_init("domain", domain_proto_mtx_grp_attr);
		
	/*
	 * allocate the lock attribute for per domain mutexes
	 */
	domain_proto_mtx_attr = lck_attr_alloc_init();

	if ((domain_proto_mtx = lck_mtx_alloc_init(domain_proto_mtx_grp, domain_proto_mtx_attr)) == NULL) {
		printf("domaininit: can't init domain mtx for domain list\n");
		return;	/* we have a problem... */
	}
	/*
	 * Add all the static domains to the domains list
	 */

	lck_mtx_lock(domain_proto_mtx);

	concat_domain(&localdomain);
	concat_domain(&routedomain);
	concat_domain(&inetdomain);
#if NETAT
	concat_domain(&atalkdomain);
#endif
#if INET6
	concat_domain(&inet6domain);
#endif
#if IPSEC
	concat_domain(&keydomain);
#endif

#if NS
	concat_domain(&nsdomain);
#endif
#if ISO
	concat_domain(&isodomain);
#endif
#if CCITT
	concat_domain(&ccittdomain);
#endif
	concat_domain(&ndrvdomain);

	concat_domain(&systemdomain);

	/*
	 * Now ask them all to init (XXX including the routing domain,
	 * see above)
	 */
	for (dp = domains; dp; dp = dp->dom_next)
		init_domain(dp);

	lck_mtx_unlock(domain_proto_mtx);
	timeout(pffasttimo, NULL, 1);
	timeout(pfslowtimo, NULL, 1);
}

struct protosw *
pffindtype(family, type)
	int family, type;
{
	register struct domain *dp;
	register struct protosw *pr;

	lck_mtx_assert(domain_proto_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(domain_proto_mtx);
	for (dp = domains; dp; dp = dp->dom_next)
		if (dp->dom_family == family)
			goto found;
	lck_mtx_unlock(domain_proto_mtx);
	return (0);
found:
	for (pr = dp->dom_protosw; pr; pr = pr->pr_next)
		if (pr->pr_type && pr->pr_type == type) {
			lck_mtx_unlock(domain_proto_mtx);
			return (pr);
		}
	lck_mtx_unlock(domain_proto_mtx);
	return (0);
}

struct domain *
pffinddomain(int pf)
{	struct domain *dp;

	lck_mtx_assert(domain_proto_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(domain_proto_mtx);
	dp = domains;
	while (dp)
	{	if (dp->dom_family == pf) {
			lck_mtx_unlock(domain_proto_mtx);
			return(dp);
		}
		dp = dp->dom_next;
	}
	lck_mtx_unlock(domain_proto_mtx);
	return(NULL);
}

struct protosw *
pffindproto(family, protocol, type)
	int family, protocol, type;
{
	register struct protosw *pr;
	lck_mtx_assert(domain_proto_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(domain_proto_mtx);
	pr = pffindproto_locked(family, protocol, type);
	lck_mtx_unlock(domain_proto_mtx);
	return (pr);
}

struct protosw *
pffindproto_locked(family, protocol, type)
	int family, protocol, type;
{
	register struct domain *dp;
	register struct protosw *pr;
	struct protosw *maybe = 0;

	if (family == 0)
		return (0);
	for (dp = domains; dp; dp = dp->dom_next)
		if (dp->dom_family == family)
			goto found;
	return (0);
found:
	for (pr = dp->dom_protosw; pr; pr = pr->pr_next) {
		if ((pr->pr_protocol == protocol) && (pr->pr_type == type))
			return (pr);

		if (type == SOCK_RAW && pr->pr_type == SOCK_RAW &&
		    pr->pr_protocol == 0 && maybe == (struct protosw *)0)
			maybe = pr;
	}
	return (maybe);
}

int
net_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
           user_addr_t newp, size_t newlen, struct proc *p)
{
	register struct domain *dp;
	register struct protosw *pr;
	int family, protocol, error;

	/*
	 * All sysctl names at this level are nonterminal;
	 * next two components are protocol family and protocol number,
	 * then at least one addition component.
	 */
	if (namelen < 3)
		return (EISDIR);		/* overloaded */
	family = name[0];
	protocol = name[1];

	if (family == 0)
		return (0);
	lck_mtx_lock(domain_proto_mtx);
	for (dp = domains; dp; dp = dp->dom_next)
		if (dp->dom_family == family)
			goto found;
	lck_mtx_unlock(domain_proto_mtx);
	return (ENOPROTOOPT);
found:
	for (pr = dp->dom_protosw; pr; pr = pr->pr_next)
		if (pr->pr_protocol == protocol && pr->pr_sysctl) {
			error = (*pr->pr_sysctl)(name + 2, namelen - 2,
			    oldp, oldlenp, newp, newlen);
			lck_mtx_unlock(domain_proto_mtx);
			return (error);
		}
	lck_mtx_unlock(domain_proto_mtx);
	return (ENOPROTOOPT);
}

void
pfctlinput(cmd, sa)
	int cmd;
	struct sockaddr *sa;
{
	pfctlinput2(cmd, sa, (void*)0);
}

void
pfctlinput2(cmd, sa, ctlparam)
	int cmd;
	struct sockaddr *sa;
	void *ctlparam;
{
	struct domain *dp;
	struct protosw *pr;

	if (!sa)
		return;

	lck_mtx_lock(domain_proto_mtx);
	for (dp = domains; dp; dp = dp->dom_next)
		for (pr = dp->dom_protosw; pr; pr = pr->pr_next)
			if (pr->pr_ctlinput)
				(*pr->pr_ctlinput)(cmd, sa, ctlparam);
	lck_mtx_unlock(domain_proto_mtx);
}

void
pfslowtimo(arg)
	void *arg;
{
	register struct domain *dp;
	register struct protosw *pr;

	lck_mtx_lock(domain_proto_mtx);
	for (dp = domains; dp; dp = dp->dom_next) 
		for (pr = dp->dom_protosw; pr; pr = pr->pr_next) {
			if (pr->pr_slowtimo)
				(*pr->pr_slowtimo)();
			if (do_reclaim && pr->pr_drain)
				(*pr->pr_drain)();
		}
	do_reclaim = 0;
	lck_mtx_unlock(domain_proto_mtx);
	timeout(pfslowtimo, NULL, hz/2);
        
}

void
pffasttimo(arg)
	void *arg;
{
	register struct domain *dp;
	register struct protosw *pr;

	lck_mtx_lock(domain_proto_mtx);
	for (dp = domains; dp; dp = dp->dom_next)
		for (pr = dp->dom_protosw; pr; pr = pr->pr_next)
			if (pr->pr_fasttimo)
				(*pr->pr_fasttimo)();
	lck_mtx_unlock(domain_proto_mtx);
	timeout(pffasttimo, NULL, hz/5);
}
