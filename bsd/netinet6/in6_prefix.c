/*	$KAME: in6_prefix.c,v 1.27 2000/03/29 23:13:13 itojun Exp $	*/

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

/*
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)in.c	8.2 (Berkeley) 11/15/93
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/proc.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/in6_prefix.h>
#include <netinet6/ip6_var.h>

#ifdef __APPLE__
#define M_IP6RR 	M_IP6MISC
#define M_RR_ADDR 	M_IP6MISC
#else
static MALLOC_DEFINE(M_IP6RR, "ip6rr", "IPv6 Router Renumbering Prefix");
static MALLOC_DEFINE(M_RR_ADDR, "rp_addr", "IPv6 Router Renumbering Ifid");
#endif

struct rr_prhead rr_prefix;

#include <net/net_osdep.h>

static void	add_each_addr(struct socket *so, struct rr_prefix *rpp,
				   struct rp_addr *rap);
static int create_ra_entry(struct rp_addr **rapp);
static int add_each_prefix(struct socket *so, struct rr_prefix *rpp);
static void free_rp_entries(struct rr_prefix *rpp);
static int link_stray_ia6s(struct rr_prefix *rpp);
static void	rp_remove(struct rr_prefix *rpp);
extern lck_mtx_t *prefix6_mutex;

/*
 * Copy bits from src to tgt, from off bit for len bits.
 * Caller must specify collect tgtsize and srcsize.
 */
static void
bit_copy(char *tgt, u_int tgtsize, char *src, u_int srcsize,
	 u_int off, u_int len)
{
	char *sp, *tp;

	/* arg values check */
	if (srcsize < off || srcsize < (off + len) ||
	    tgtsize < off || tgtsize < (off + len)) {
		log(LOG_ERR,
		    "in6_prefix.c: bit_copy: invalid args: srcsize %d,\n"
		    "tgtsize %d, off %d, len %d\n", srcsize, tgtsize, off,
		    len);
		return;
	}

	/* search start point */
	for (sp = src, tp = tgt; off >= 8; sp++, tp++)
		off-=8;
	/* copy starting bits */
	if (off) {
		char setbit;
		int startbits;

		startbits = min((8 - off), len);

		for (setbit = (0x80 >> off); startbits;
		     setbit >>= 1, startbits--, len--)
				*tp  |= (setbit & *sp);
		tp++;
		sp++;
	}
	/* copy midium bits */
	for (; len >= 8; sp++, tp++) {
		*tp = *sp;
		len-=8;
	}
	/* copy ending bits */
	if (len) {
		char setbit;

		for (setbit = 0x80; len; setbit >>= 1, len--)
			*tp  |= (setbit & *sp);
	}
}

static struct ifprefix *
in6_prefixwithifp(struct ifnet *ifp, int plen, struct in6_addr *dst)
{
	struct ifprefix *ifpr;

	/* search matched prefix */
	ifnet_lock_shared(ifp);
	for (ifpr = TAILQ_FIRST(&ifp->if_prefixhead); ifpr;
	     ifpr = TAILQ_NEXT(ifpr, ifpr_list))
	{
		if (ifpr->ifpr_prefix->sa_family != AF_INET6 ||
		    ifpr->ifpr_type != IN6_PREFIX_RR)
 			continue;
		if (plen <= in6_matchlen(dst, IFPR_IN6(ifpr)))
			break;
	}
	ifnet_lock_done(ifp);
	return (ifpr);
}

/*
 * Search prefix which matches arg prefix as specified in
 * draft-ietf-ipngwg-router-renum-08.txt
 */
static struct rr_prefix *
search_matched_prefix(struct ifnet *ifp, struct in6_prefixreq *ipr)
{
	struct ifprefix *ifpr;
	struct ifaddr *ifa;
	struct rr_prefix *rpp;

	/* search matched prefix */
	ifpr = in6_prefixwithifp(ifp, ipr->ipr_plen,
				 &ipr->ipr_prefix.sin6_addr);
	if (ifpr != NULL)
		return ifpr2rp(ifpr);

	/*
	 * search matched addr, and then search prefix
	 * which matches the addr
	 */

	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
	{
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (ipr->ipr_plen <=
		    in6_matchlen(&ipr->ipr_prefix.sin6_addr, IFA_IN6(ifa)))
			break;
	}
	if (ifa == NULL) {
		ifnet_lock_done(ifp);
		return NULL;
	}

	rpp = ifpr2rp(((struct in6_ifaddr *)ifa)->ia6_ifpr);
	if (rpp != 0) {
		ifnet_lock_done(ifp);
		return rpp;
	}
	
	for (ifpr = TAILQ_FIRST(&ifp->if_prefixhead); ifpr;
	     ifpr = TAILQ_NEXT(ifpr, ifpr_list))
	{
		if (ifpr->ifpr_prefix->sa_family != AF_INET6 ||
		    ifpr->ifpr_type != IN6_PREFIX_RR)
			continue;
		if (ifpr->ifpr_plen <= in6_matchlen(IFA_IN6(ifa),
						    IFPR_IN6(ifpr)))
			break;
	}
	ifnet_lock_done(ifp);
	if (ifpr != NULL)
		log(LOG_ERR,  "in6_prefix.c: search_matched_prefix: addr %s"
		    "has no pointer to prefix %s\n", ip6_sprintf(IFA_IN6(ifa)),
		    ip6_sprintf(IFPR_IN6(ifpr)));
	return ifpr2rp(ifpr);
}

/*
 * Search prefix which matches arg prefix as specified in
 * draft-ietf-ipngwg-router-renum-08.txt, and mark it if exists.
 * Return 1 if anything matched, and 0 if nothing matched.
 */
static int
mark_matched_prefixes(u_long cmd, struct ifnet *ifp, struct in6_rrenumreq *irr)
{
	struct ifprefix *ifpr;
	struct ifaddr *ifa;
	int matchlen, matched = 0;

	/* search matched prefixes */
	ifnet_lock_exclusive(ifp);	/* Should if_prefixhead be protected by IPv6?? */
	for (ifpr = TAILQ_FIRST(&ifp->if_prefixhead); ifpr;
	     ifpr = TAILQ_NEXT(ifpr, ifpr_list))
	{
		if (ifpr->ifpr_prefix->sa_family != AF_INET6 ||
		    ifpr->ifpr_type != IN6_PREFIX_RR)
			continue;
		matchlen = in6_matchlen(&irr->irr_matchprefix.sin6_addr,
					IFPR_IN6(ifpr));
		if (irr->irr_m_minlen > ifpr->ifpr_plen ||
		    irr->irr_m_maxlen < ifpr->ifpr_plen ||
		    irr->irr_m_len > matchlen)
 			continue;
		matched = 1;
		ifpr2rp(ifpr)->rp_statef_addmark = 1;
		if (cmd == SIOCCIFPREFIX_IN6)
			ifpr2rp(ifpr)->rp_statef_delmark = 1;
	}

	/*
	 * search matched addr, and then search prefixes
	 * which matche the addr
	 */
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
	{
		struct rr_prefix *rpp;

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		matchlen = in6_matchlen(&irr->irr_matchprefix.sin6_addr,
					IFA_IN6(ifa));
		if (irr->irr_m_minlen > matchlen ||
		    irr->irr_m_maxlen < matchlen || irr->irr_m_len > matchlen)
 			continue;
		rpp = ifpr2rp(((struct in6_ifaddr *)ifa)->ia6_ifpr);
		if (rpp != 0) {
			matched = 1;
			rpp->rp_statef_addmark = 1;
			if (cmd == SIOCCIFPREFIX_IN6)
				rpp->rp_statef_delmark = 1;
		} else
			log(LOG_WARNING, "in6_prefix.c: mark_matched_prefixes:"
			    "no back pointer to ifprefix for %s. "
			    "ND autoconfigured addr?\n",
			    ip6_sprintf(IFA_IN6(ifa)));
	}
	ifnet_lock_done(ifp);
	return matched;
}

/*
 * Mark global prefixes as to be deleted.
 */
static void
delmark_global_prefixes(struct ifnet *ifp, struct in6_rrenumreq *irr)
{
	struct ifprefix *ifpr;

	/* search matched prefixes */
	ifnet_lock_exclusive(ifp);
	for (ifpr = TAILQ_FIRST(&ifp->if_prefixhead); ifpr;
	     ifpr = TAILQ_NEXT(ifpr, ifpr_list))
	{
		if (ifpr->ifpr_prefix->sa_family != AF_INET6 ||
		    ifpr->ifpr_type != IN6_PREFIX_RR)
			continue;
		/* mark delete global prefix */
		if (in6_addrscope(RP_IN6(ifpr2rp(ifpr))) ==
		    IPV6_ADDR_SCOPE_GLOBAL)
			ifpr2rp(ifpr)->rp_statef_delmark = 1;
	}
	ifnet_lock_done(ifp);
}

/* Unmark prefixes */
static void
unmark_prefixes(struct ifnet *ifp)
{
	struct ifprefix *ifpr;

	/* unmark all prefix */
	ifnet_lock_exclusive(ifp);
	for (ifpr = TAILQ_FIRST(&ifp->if_prefixhead); ifpr;
	     ifpr = TAILQ_NEXT(ifpr, ifpr_list))
	{
		if (ifpr->ifpr_prefix->sa_family != AF_INET6 ||
		    ifpr->ifpr_type != IN6_PREFIX_RR)
 			continue;
		/* unmark prefix */
		ifpr2rp(ifpr)->rp_statef_addmark = 0;
		ifpr2rp(ifpr)->rp_statef_delmark = 0;
	}
	ifnet_lock_done(ifp);
}

static void
init_prefix_ltimes(struct rr_prefix *rpp)
{
	struct timeval timenow;

	getmicrotime(&timenow);

	if (rpp->rp_pltime == RR_INFINITE_LIFETIME ||
	    rpp->rp_rrf_decrprefd == 0)
		rpp->rp_preferred = 0;
	else
		rpp->rp_preferred = timenow.tv_sec + rpp->rp_pltime;
	if (rpp->rp_vltime == RR_INFINITE_LIFETIME ||
	    rpp->rp_rrf_decrvalid == 0)
		rpp->rp_expire = 0;
	else
		rpp->rp_expire = timenow.tv_sec + rpp->rp_vltime;
}

static int
rr_are_ifid_equal(struct in6_addr *ii1, struct in6_addr *ii2, int ii_len)
{
	int ii_bytelen, ii_bitlen;
	int p_bytelen, p_bitlen;

	/* sanity check */
	if (1 > ii_len ||
	    ii_len > 124) { /* as RFC2373, prefix is at least 4 bit */
		log(LOG_ERR, "rr_are_ifid_equal: invalid ifid length(%d)\n",
		    ii_len);
		return(0);
	}

	ii_bytelen = ii_len / 8;
	ii_bitlen = ii_len % 8;

	p_bytelen = sizeof(struct in6_addr) - ii_bytelen - 1;
	p_bitlen = 8 - ii_bitlen;

	if (bcmp(ii1->s6_addr + p_bytelen + 1, ii2->s6_addr + p_bytelen + 1,
		 ii_bytelen))
		return(0);
	if (((ii1->s6_addr[p_bytelen] << p_bitlen) & 0xff) !=
	    ((ii2->s6_addr[p_bytelen] << p_bitlen) & 0xff))
		return(0);

	return(1);
}

static struct rp_addr *
search_ifidwithprefix(struct rr_prefix *rpp, struct in6_addr *ifid)
{
	struct rp_addr *rap;

	lck_mtx_lock(prefix6_mutex);
	LIST_FOREACH(rap, &rpp->rp_addrhead, ra_entry)
	{
		if (rr_are_ifid_equal(ifid, &rap->ra_ifid,
				      (sizeof(struct in6_addr) << 3) -
				      rpp->rp_plen))
			break;
	}
	lck_mtx_unlock(prefix6_mutex);
	return rap;
}

static int
assign_ra_entry(struct rr_prefix *rpp, int iilen, struct in6_ifaddr *ia)
{
	int error = 0;
	struct rp_addr *rap;
	int s;

	if ((error = create_ra_entry(&rap)) != 0)
		return error;

	/* copy interface id part */
	bit_copy((caddr_t)&rap->ra_ifid, sizeof(rap->ra_ifid) << 3,
		 (caddr_t)IA6_IN6(ia),
		 sizeof(*IA6_IN6(ia)) << 3, rpp->rp_plen, iilen);
	/* link to ia, and put into list */
	rap->ra_addr = ia;
	ifaref(&rap->ra_addr->ia_ifa);
#if 0 /* Can't do this now, because rpp may be on th stack. should fix it? */
	ia->ia6_ifpr = rp2ifpr(rpp);
#endif
	lck_mtx_lock(prefix6_mutex);
	LIST_INSERT_HEAD(&rpp->rp_addrhead, rap, ra_entry);
	lck_mtx_unlock(prefix6_mutex);

	return 0;
}

/*
 * add a link-local address to an interface.  we will add new interface address
 * (prefix database + new interface id).
 */
static int
in6_prefix_add_llifid(int iilen, struct in6_ifaddr *ia)
{
	struct rr_prefix *rpp;
	struct rp_addr *rap;
	struct socket so;
	int error;

	if ((error = create_ra_entry(&rap)) != 0)
		return(error);
	/* copy interface id part */
	bit_copy((caddr_t)&rap->ra_ifid, sizeof(rap->ra_ifid) << 3,
		 (caddr_t)IA6_IN6(ia), sizeof(*IA6_IN6(ia)) << 3,
		 64, (sizeof(rap->ra_ifid) << 3) - 64);
	/* XXX: init dummy so */
	bzero(&so, sizeof(so));
	/* insert into list */
	lck_mtx_lock(prefix6_mutex);
	LIST_FOREACH(rpp, &rr_prefix, rp_entry)
	{
		/*
		 * do not attempt to add an address, if ifp does not match
		 */
		if (rpp->rp_ifp != ia->ia_ifp)
			continue;

		LIST_INSERT_HEAD(&rpp->rp_addrhead, rap, ra_entry);
		add_each_addr(&so, rpp, rap);
	}
	lck_mtx_unlock(prefix6_mutex);
	return 0;
}

/*
 * add an address to an interface.  if the interface id portion is new,
 * we will add new interface address (prefix database + new interface id).
 */
int
in6_prefix_add_ifid(int iilen, struct in6_ifaddr *ia)
{
	int plen = (sizeof(*IA6_IN6(ia)) << 3) - iilen;
	struct ifprefix *ifpr;
	struct rp_addr *rap;
	int error = 0;

	if (IN6_IS_ADDR_LINKLOCAL(IA6_IN6(ia)))
		return(in6_prefix_add_llifid(iilen, ia));
	ifpr = in6_prefixwithifp(ia->ia_ifp, plen, IA6_IN6(ia));
	if (ifpr == NULL) {
		struct rr_prefix rp;
		struct socket so;
		int pplen = (plen == 128) ? 64 : plen; /* XXX hardcoded 64 is bad */

		/* allocate a prefix for ia, with default properties */

		/* init rp */
		bzero(&rp, sizeof(rp));
		rp.rp_type = IN6_PREFIX_RR;
		rp.rp_ifp = ia->ia_ifp;
		rp.rp_plen = pplen;
		rp.rp_prefix.sin6_len = sizeof(rp.rp_prefix);
		rp.rp_prefix.sin6_family = AF_INET6;
		bit_copy((char *)RP_IN6(&rp), sizeof(*RP_IN6(&rp)) << 3,
			 (char *)&ia->ia_addr.sin6_addr,
			 sizeof(ia->ia_addr.sin6_addr) << 3,
			 0, pplen);
		rp.rp_vltime = rp.rp_pltime = RR_INFINITE_LIFETIME;
		rp.rp_raf_onlink = 1;
		rp.rp_raf_auto = 1;
		/* Is some FlagMasks for rrf necessary? */
		rp.rp_rrf_decrvalid = rp.rp_rrf_decrprefd = 0;
		rp.rp_origin = PR_ORIG_RR; /* can be renumbered */

		/* create ra_entry */
		error = link_stray_ia6s(&rp);
		if (error != 0) {
			free_rp_entries(&rp);
			return error;
		}

		/* XXX: init dummy so */
		bzero(&so, sizeof(so));

		error = add_each_prefix(&so, &rp);

		/* free each rp_addr entry */
		free_rp_entries(&rp);

		if (error != 0)
			return error;

		/* search again */
		ifpr = in6_prefixwithifp(ia->ia_ifp, pplen, IA6_IN6(ia));
		if (ifpr == NULL)
			return 0;
	}
	rap = search_ifidwithprefix(ifpr2rp(ifpr), IA6_IN6(ia));
	if (rap != NULL) {
		if (rap->ra_addr == NULL) {
			rap->ra_addr = ia;
			ifaref(&rap->ra_addr->ia_ifa);
		} else if (rap->ra_addr != ia) {
			/* There may be some inconsistencies between addrs. */
			log(LOG_ERR, "ip6_prefix.c: addr %s/%d matched prefix"
			    " already has another ia %p(%s) on its ifid list\n",
			    ip6_sprintf(IA6_IN6(ia)), plen,
			    rap->ra_addr,
			    ip6_sprintf(IA6_IN6(rap->ra_addr)));
			return EADDRINUSE /* XXX */;
		}
		ia->ia6_ifpr = ifpr;
		return 0;
	}
	error = assign_ra_entry(ifpr2rp(ifpr), iilen, ia);
	if (error == 0)
		ia->ia6_ifpr = ifpr;
	return (error);
}

void
in6_prefix_remove_ifid(int iilen, struct in6_ifaddr *ia)
{
	struct rp_addr *rap;

	if (ia->ia6_ifpr == NULL)
		return;
	rap = search_ifidwithprefix(ifpr2rp(ia->ia6_ifpr), IA6_IN6(ia));
	if (rap != NULL) {
		lck_mtx_lock(prefix6_mutex);
		LIST_REMOVE(rap, ra_entry);
		lck_mtx_unlock(prefix6_mutex);
		if (rap->ra_addr)
			ifafree(&rap->ra_addr->ia_ifa);
		FREE(rap, M_RR_ADDR);
	}

	if (LIST_EMPTY(&ifpr2rp(ia->ia6_ifpr)->rp_addrhead))
		rp_remove(ifpr2rp(ia->ia6_ifpr));
}

void
in6_purgeprefix(
	struct ifnet *ifp)
{
	struct ifprefix *ifpr, *nextifpr;

	/* delete prefixes before ifnet goes away */
	ifnet_lock_exclusive(ifp);
	for (ifpr = TAILQ_FIRST(&ifp->if_prefixhead); ifpr;
	     ifpr = nextifpr)
	{
		nextifpr = TAILQ_NEXT(ifpr, ifpr_list);
		if (ifpr->ifpr_prefix->sa_family != AF_INET6 ||
		    ifpr->ifpr_type != IN6_PREFIX_RR)
 			continue;
		(void)delete_each_prefix(ifpr2rp(ifpr), PR_ORIG_KERNEL);
	}
	ifnet_lock_done(ifp);
}

static void
add_each_addr(struct socket *so, struct rr_prefix *rpp, struct rp_addr *rap)
{
	struct in6_ifaddr *ia6;
	struct in6_aliasreq ifra;
	int error;

	/* init ifra */
	bzero(&ifra, sizeof(ifra));
	strncpy(ifra.ifra_name, if_name(rpp->rp_ifp), sizeof(ifra.ifra_name));
	ifra.ifra_addr.sin6_family = ifra.ifra_prefixmask.sin6_family =
		AF_INET6;
	ifra.ifra_addr.sin6_len = ifra.ifra_prefixmask.sin6_len =
		sizeof(ifra.ifra_addr);
	/* copy prefix part */
	bit_copy((char *)&ifra.ifra_addr.sin6_addr,
		 sizeof(ifra.ifra_addr.sin6_addr) << 3,
		 (char *)RP_IN6(rpp), sizeof(*RP_IN6(rpp)) << 3,
		 0, rpp->rp_plen);
	/* copy interface id part */
	bit_copy((char *)&ifra.ifra_addr.sin6_addr,
		 sizeof(ifra.ifra_addr.sin6_addr) << 3,
		 (char *)&rap->ra_ifid, sizeof(rap->ra_ifid) << 3,
		 rpp->rp_plen, (sizeof(rap->ra_ifid) << 3) - rpp->rp_plen);
	in6_prefixlen2mask(&ifra.ifra_prefixmask.sin6_addr, rpp->rp_plen);
	/* don't care ifra_flags for now */

	/*
	 * XXX: if we did this with finite lifetime values, the lifetimes would
	 *      decrese in time and never incremented.
	 *      we should need more clarifications on the prefix mechanism...
	 */
	ifra.ifra_lifetime.ia6t_vltime = rpp->rp_vltime;
	ifra.ifra_lifetime.ia6t_pltime = rpp->rp_pltime;

	ia6 = in6ifa_ifpwithaddr(rpp->rp_ifp, &ifra.ifra_addr.sin6_addr);
	if (ia6 != NULL) {
		if (ia6->ia6_ifpr == NULL) {
			/* link this addr and the prefix each other */
			if (rap->ra_addr)
				ifafree(&rap->ra_addr->ia_ifa);
			rap->ra_addr = ia6;
			ifaref(&rap->ra_addr->ia_ifa);
			ia6->ia6_ifpr = rp2ifpr(rpp);
			return;
		}
		if (ia6->ia6_ifpr == rp2ifpr(rpp)) {
			if (rap->ra_addr)
				ifafree(&rap->ra_addr->ia_ifa);
			rap->ra_addr = ia6;
			ifaref(&rap->ra_addr->ia_ifa);
			return;
		}
		/*
		 * The addr is already assigned to other
		 * prefix.
		 * There may be some inconsistencies between
		 * prefixes.
		 * e.g. overraped prefixes with common starting
		 *      part and different plefixlen.
		 *      Or, completely duplicated prefixes?
		 * log it and return.
		 */
		log(LOG_ERR,
		    "in6_prefix.c: add_each_addr: addition of an addr %s/%d "
		    "failed because there is already another addr %s/%d\n",
		    ip6_sprintf(&ifra.ifra_addr.sin6_addr), rpp->rp_plen,
		    ip6_sprintf(IA6_IN6(ia6)),
		    in6_mask2len(&ia6->ia_prefixmask.sin6_addr, NULL));
		return;
	}
	/* propagate ANYCAST flag if it is set for ancestor addr */
	if (rap->ra_flags.anycast != 0)
		ifra.ifra_flags |= IN6_IFF_ANYCAST;
	error = in6_control(so, SIOCAIFADDR_IN6, (caddr_t)&ifra, rpp->rp_ifp,
			    current_proc());
	if (error != 0) {
		log(LOG_ERR, "in6_prefix.c: add_each_addr: addition of an addr"
		    "%s/%d failed because in6_control failed for error %d\n",
		    ip6_sprintf(&ifra.ifra_addr.sin6_addr), rpp->rp_plen,
		    error);
		return;
	}

	/*
	 * link beween this addr and the prefix will be done
	 * in in6_prefix_add_ifid
	 */
}

static int
rrpr_update(struct socket *so, struct rr_prefix *new)
{
	struct rr_prefix *rpp;
	struct ifprefix *ifpr;
	struct rp_addr *rap;
	int s;

	/* search existing prefix */
	ifnet_lock_exclusive(new->rp_ifp);
	for (ifpr = TAILQ_FIRST(&new->rp_ifp->if_prefixhead); ifpr;
	     ifpr = TAILQ_NEXT(ifpr, ifpr_list))
	{
		if (ifpr->ifpr_prefix->sa_family != AF_INET6 ||
		    ifpr->ifpr_type != IN6_PREFIX_RR)
 			continue;
		if (ifpr->ifpr_plen == new->rp_plen &&
		    in6_are_prefix_equal(IFPR_IN6(ifpr), RP_IN6(new),
					 ifpr->ifpr_plen))
			break;
	}
	rpp = ifpr2rp(ifpr);
	if (rpp != NULL) {
		/*
		 * We got a prefix which we have seen in the past.
		 */
		/*
		 * If the origin of the already-installed prefix is more
		 * preferable than the new one, ignore installation request.
		 */
		if (rpp->rp_origin > new->rp_origin) {
			ifnet_lock_done(new->rp_ifp);
			return(EPERM);
		}

		/* update prefix information */
		rpp->rp_flags.prf_ra = new->rp_flags.prf_ra;
		if (rpp->rp_origin >= PR_ORIG_RR)
			rpp->rp_flags.prf_rr = new->rp_flags.prf_rr;
		rpp->rp_vltime = new->rp_vltime;
		rpp->rp_pltime = new->rp_pltime;
		rpp->rp_expire = new->rp_expire;
		rpp->rp_preferred = new->rp_preferred;
		rpp->rp_statef_delmark = 0; /* cancel deletion */
		/*
		 * Interface id related update.
		 *  add rp_addr entries in new into rpp, if they have not
		 *  been already included in rpp.
		 */
		lck_mtx_lock(prefix6_mutex);
		while (!LIST_EMPTY(&new->rp_addrhead))
		{
			rap = LIST_FIRST(&new->rp_addrhead);
			LIST_REMOVE(rap, ra_entry);
			if (search_ifidwithprefix(rpp, &rap->ra_ifid)
			    != NULL) {
				if (rap->ra_addr)
					ifafree(&rap->ra_addr->ia_ifa);
				FREE(rap, M_RR_ADDR);
				continue;
			}
			LIST_INSERT_HEAD(&rpp->rp_addrhead, rap, ra_entry);
		}
		lck_mtx_unlock(prefix6_mutex);
	} else {
		/*
		 * We got a fresh prefix.
		 */
		/* create new prefix */
		rpp = (struct rr_prefix *)_MALLOC(sizeof(*rpp), M_IP6RR,
						 M_NOWAIT);
		if (rpp == NULL) {
			log(LOG_ERR, "in6_prefix.c: rrpr_update:%d"
			    ": ENOBUFS for rr_prefix\n", __LINE__);
			ifnet_lock_done(new->rp_ifp);
			return(ENOBUFS);
		}
		/* initilization */
		lck_mtx_lock(prefix6_mutex);
		*rpp = *new;
		LIST_INIT(&rpp->rp_addrhead);
		/*  move rp_addr entries of new to rpp */
		while (!LIST_EMPTY(&new->rp_addrhead))
		{
			rap = LIST_FIRST(&new->rp_addrhead);
			LIST_REMOVE(rap, ra_entry);
			LIST_INSERT_HEAD(&rpp->rp_addrhead, rap, ra_entry);
		}
		lck_mtx_unlock(prefix6_mutex);

		/* let rp_ifpr.ifpr_prefix point rr_prefix. */
		rpp->rp_ifpr.ifpr_prefix = (struct sockaddr *)&rpp->rp_prefix;
		/* link rr_prefix entry to if_prefixlist */
		{
			struct ifnet *ifp = rpp->rp_ifp;
			struct ifprefix *ifpr;

			if ((ifpr = TAILQ_FIRST(&ifp->if_prefixhead))
			    != NULL) {
				for ( ; TAILQ_NEXT(ifpr, ifpr_list);
				      ifpr = TAILQ_NEXT(ifpr, ifpr_list))
					continue;
				TAILQ_NEXT(ifpr, ifpr_list) = rp2ifpr(rpp);
			} else
				TAILQ_FIRST(&ifp->if_prefixhead) =
					rp2ifpr(rpp);
			rp2ifpr(rpp)->ifpr_type = IN6_PREFIX_RR;
		}
		/* link rr_prefix entry to rr_prefix list */
		lck_mtx_lock(prefix6_mutex);
		LIST_INSERT_HEAD(&rr_prefix, rpp, rp_entry);
		lck_mtx_unlock(prefix6_mutex);
	}
	ifnet_lock_done(new->rp_ifp);

	if (!new->rp_raf_auto)
		return 0;

	/*
	 * Add an address for each interface id, if it is not yet
	 * If it existed but not pointing to the prefix yet,
	 * init the prefix pointer.
	 */
	lck_mtx_lock(prefix6_mutex);
	LIST_FOREACH(rap, &rpp->rp_addrhead, ra_entry)
	{
		if (rap->ra_addr != NULL) {
			if (rap->ra_addr->ia6_ifpr == NULL)
				rap->ra_addr->ia6_ifpr = rp2ifpr(rpp);
			continue;
		}
		add_each_addr(so, rpp, rap);
	}
	lck_mtx_unlock(prefix6_mutex);
	return 0;
}

static int
add_each_prefix(struct socket *so, struct rr_prefix *rpp)
{
	init_prefix_ltimes(rpp);
	return(rrpr_update(so, rpp));
}

static void
rp_remove(struct rr_prefix *rpp)
{

	/* unlink rp_entry from if_prefixlist */
	lck_mtx_lock(prefix6_mutex);
	{
		struct ifnet *ifp = rpp->rp_ifp;
		struct ifprefix *ifpr;

		ifnet_lock_exclusive(ifp);
		if ((ifpr = TAILQ_FIRST(&ifp->if_prefixhead)) == rp2ifpr(rpp))
			TAILQ_FIRST(&ifp->if_prefixhead) =
				TAILQ_NEXT(ifpr, ifpr_list);
		else {
			while (TAILQ_NEXT(ifpr, ifpr_list) != NULL &&
			       (TAILQ_NEXT(ifpr, ifpr_list) != rp2ifpr(rpp)))
				ifpr = TAILQ_NEXT(ifpr, ifpr_list);
			if (TAILQ_NEXT(ifpr, ifpr_list))
				TAILQ_NEXT(ifpr, ifpr_list) =
					TAILQ_NEXT(rp2ifpr(rpp), ifpr_list);
 			else
 				printf("Couldn't unlink rr_prefix from ifp\n");
		}
		ifnet_lock_done(ifp);
	}
	/* unlink rp_entry from rr_prefix list */
	LIST_REMOVE(rpp, rp_entry);
	lck_mtx_unlock(prefix6_mutex);
	FREE(rpp, M_IP6RR);
}

static int
create_ra_entry(struct rp_addr **rapp)
{
	*rapp = (struct rp_addr *)_MALLOC(sizeof(struct rp_addr), M_RR_ADDR,
					 M_NOWAIT);
	if (*rapp == NULL) {
		log(LOG_ERR, "in6_prefix.c: init_newprefix:%d: ENOBUFS"
		    "for rp_addr\n", __LINE__);
		return ENOBUFS;
	}
	bzero(*rapp, sizeof(*(*rapp)));

	return 0;
}

static int
init_newprefix(struct in6_rrenumreq *irr, struct ifprefix *ifpr,
	       struct rr_prefix *rpp)
{
	struct rp_addr *orap;

	/* init rp */
	bzero(rpp, sizeof(*rpp));
	rpp->rp_type = IN6_PREFIX_RR;
	rpp->rp_ifp = ifpr->ifpr_ifp;
	rpp->rp_plen = ifpr->ifpr_plen;
	rpp->rp_prefix.sin6_len = sizeof(rpp->rp_prefix);
	rpp->rp_prefix.sin6_family = AF_INET6;
	bit_copy((char *)RP_IN6(rpp), sizeof(*RP_IN6(rpp)) << 3,
		 (char *)&irr->irr_useprefix.sin6_addr,
		 sizeof(irr->irr_useprefix.sin6_addr) << 3,
		 0, irr->irr_u_uselen);
	/* copy keeplen part if necessary as necessary len */
	if (irr->irr_u_uselen < ifpr->ifpr_plen)
		bit_copy((char *)RP_IN6(rpp), sizeof(*RP_IN6(rpp)) << 3,
			 (char *)IFPR_IN6(ifpr), sizeof(*IFPR_IN6(ifpr)) << 3,
			 irr->irr_u_uselen,
			 min(ifpr->ifpr_plen - irr->irr_u_uselen,
			     irr->irr_u_keeplen));
	lck_mtx_lock(prefix6_mutex);
	LIST_FOREACH(orap, &(ifpr2rp(ifpr)->rp_addrhead), ra_entry)
	{
		struct rp_addr *rap;
		int error = 0;

		if ((error = create_ra_entry(&rap)) != 0)
			return error;
		rap->ra_ifid = orap->ra_ifid;
		rap->ra_flags.anycast = (orap->ra_addr != NULL &&
					 (orap->ra_addr->ia6_flags &
					  IN6_IFF_ANYCAST) != 0) ? 1 : 0;
		LIST_INSERT_HEAD(&rpp->rp_addrhead, rap, ra_entry);
	}
	rpp->rp_vltime = irr->irr_vltime;
	rpp->rp_pltime = irr->irr_pltime;
	rpp->rp_raf_onlink = irr->irr_raf_mask_onlink ? irr->irr_raf_onlink :
		ifpr2rp(ifpr)->rp_raf_onlink;
	rpp->rp_raf_auto = irr->irr_raf_mask_auto ? irr->irr_raf_auto :
		ifpr2rp(ifpr)->rp_raf_auto;
	/* Is some FlagMasks for rrf necessary? */
	rpp->rp_rrf = irr->irr_rrf;
	rpp->rp_origin = irr->irr_origin;
	lck_mtx_unlock(prefix6_mutex);

	return 0;
}

static void
free_rp_entries(struct rr_prefix *rpp)
{
	/*
	 * This func is only called with rpp on stack(not on list).
	 * So no splnet() here
	 */
	lck_mtx_lock(prefix6_mutex);
	while (!LIST_EMPTY(&rpp->rp_addrhead))
	{
		struct rp_addr *rap;

		rap = LIST_FIRST(&rpp->rp_addrhead);
		LIST_REMOVE(rap, ra_entry);
		if (rap->ra_addr)
			ifafree(&rap->ra_addr->ia_ifa);
		FREE(rap, M_RR_ADDR);
	}
	lck_mtx_unlock(prefix6_mutex);
}

static int
add_useprefixes(struct socket *so, struct ifnet *ifp,
		struct in6_rrenumreq *irr)
{
	struct ifprefix *ifpr, *nextifpr;
	struct rr_prefix rp;
	int error = 0;

	/* add prefixes to each of marked prefix */
	ifnet_lock_exclusive(ifp);
	for (ifpr = TAILQ_FIRST(&ifp->if_prefixhead); ifpr; ifpr = nextifpr)
	{
		nextifpr = TAILQ_NEXT(ifpr, ifpr_list);
		if (ifpr->ifpr_prefix->sa_family != AF_INET6 ||
		    ifpr->ifpr_type != IN6_PREFIX_RR)
 			continue;
		if (ifpr2rp(ifpr)->rp_statef_addmark) {
			if ((error = init_newprefix(irr, ifpr, &rp)) != 0)
				break;
			error = add_each_prefix(so, &rp);
		}
	}
	ifnet_lock_done(ifp);
	/* free each rp_addr entry */
	free_rp_entries(&rp);

	return error;
}

static void
unprefer_prefix(struct rr_prefix *rpp)
{
	struct rp_addr *rap;
	struct timeval timenow;

	getmicrotime(&timenow);

	lck_mtx_lock(prefix6_mutex);
	for (rap = rpp->rp_addrhead.lh_first; rap != NULL;
	     rap = rap->ra_entry.le_next) {
		if (rap->ra_addr == NULL)
			continue;
		rap->ra_addr->ia6_lifetime.ia6t_preferred = timenow.tv_sec;
		rap->ra_addr->ia6_lifetime.ia6t_pltime = 0;
	}
	lck_mtx_unlock(prefix6_mutex);

}

int
delete_each_prefix(struct rr_prefix *rpp, u_char origin)
{
	int error = 0;

	if (rpp->rp_origin > origin)
		return(EPERM);

	lck_mtx_lock(prefix6_mutex);
	while (rpp->rp_addrhead.lh_first != NULL) {
		struct rp_addr *rap;
		int s;

		rap = LIST_FIRST(&rpp->rp_addrhead);
		if (rap == NULL) {
			break;
		}
		LIST_REMOVE(rap, ra_entry);
		if (rap->ra_addr == NULL) {
			FREE(rap, M_RR_ADDR);
			continue;
		}
		rap->ra_addr->ia6_ifpr = NULL;

		in6_purgeaddr(&rap->ra_addr->ia_ifa, 0);
		ifafree(&rap->ra_addr->ia_ifa);
		FREE(rap, M_RR_ADDR);
	}
	rp_remove(rpp);
	lck_mtx_unlock(prefix6_mutex);

	return error;
}

static void
delete_prefixes(struct ifnet *ifp, u_char origin)
{
	struct ifprefix *ifpr, *nextifpr;

	/* delete prefixes marked as tobe deleted */
	ifnet_lock_exclusive(ifp);
	for (ifpr = TAILQ_FIRST(&ifp->if_prefixhead); ifpr; ifpr = nextifpr)
	{
		nextifpr = TAILQ_NEXT(ifpr, ifpr_list);
		if (ifpr->ifpr_prefix->sa_family != AF_INET6 ||
		    ifpr->ifpr_type != IN6_PREFIX_RR)
 			continue;
		if (ifpr2rp(ifpr)->rp_statef_delmark)
			(void)delete_each_prefix(ifpr2rp(ifpr), origin);
	}
	ifnet_lock_done(ifp);
}

static int
link_stray_ia6s(struct rr_prefix *rpp)
{
	struct ifaddr *ifa;

	for (ifa = rpp->rp_ifp->if_addrlist.tqh_first; ifa;
	     ifa = ifa->ifa_list.tqe_next)
	{
		struct rp_addr *rap;
		struct rr_prefix *orpp;
		int error = 0;

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (rpp->rp_plen > in6_matchlen(RP_IN6(rpp), IFA_IN6(ifa)))
			continue;

		orpp = ifpr2rp(((struct in6_ifaddr *)ifa)->ia6_ifpr);
		if (orpp != NULL) {
			if (!in6_are_prefix_equal(RP_IN6(orpp), RP_IN6(rpp),
						  rpp->rp_plen))
				log(LOG_ERR, "in6_prefix.c: link_stray_ia6s:"
				    "addr %s/%d already linked to a prefix"
				    "and it matches also %s/%d\n",
				    ip6_sprintf(IFA_IN6(ifa)), orpp->rp_plen,
				    ip6_sprintf(RP_IN6(rpp)),
				    rpp->rp_plen);
			continue;
		}
		if ((error = assign_ra_entry(rpp,
					      (sizeof(rap->ra_ifid) << 3) -
					      rpp->rp_plen,
					      (struct in6_ifaddr *)ifa)) != 0)
			return error;
	}
	return 0;
}

/* XXX assumes that permission is already checked by the caller */
int
in6_prefix_ioctl(struct socket *so, u_long cmd, caddr_t data,
		 struct ifnet *ifp)
{
	struct rr_prefix *rpp, rp_tmp;
	struct rp_addr *rap;
	struct in6_prefixreq *ipr = (struct in6_prefixreq *)data;
	struct in6_rrenumreq *irr = (struct in6_rrenumreq *)data;
	struct ifaddr *ifa;
	int error = 0;

	/*
	 * Failsafe for erroneous address config program.
	 * Let's hope rrenumd don't make a mistakes.
	 */
	if (ipr->ipr_origin <= PR_ORIG_RA)
		ipr->ipr_origin = PR_ORIG_STATIC;

	switch (cmd) {
	case SIOCSGIFPREFIX_IN6:
		delmark_global_prefixes(ifp, irr);
		/* FALL THROUGH */
	case SIOCAIFPREFIX_IN6:
	case SIOCCIFPREFIX_IN6:
		/* check if preferred lifetime > valid lifetime */
		if (irr->irr_pltime > irr->irr_vltime) {
			log(LOG_NOTICE,
			    "in6_prefix_ioctl: preferred lifetime"
			    "(%ld) is greater than valid lifetime(%ld)\n",
			    (u_long)irr->irr_pltime, (u_long)irr->irr_vltime);
			error = EINVAL;
			break;
		}
		if (mark_matched_prefixes(cmd, ifp, irr)) {
			if (irr->irr_u_uselen != 0)
				if ((error = add_useprefixes(so, ifp, irr))
				    != 0)
					goto failed;
			if (cmd != SIOCAIFPREFIX_IN6)
				delete_prefixes(ifp, irr->irr_origin);
		} else
			return (EADDRNOTAVAIL);
	failed:
		unmark_prefixes(ifp);
		break;
	case SIOCGIFPREFIX_IN6:
		rpp = search_matched_prefix(ifp, ipr);
		if (rpp == NULL || ifp != rpp->rp_ifp)
			return (EADDRNOTAVAIL);

		ipr->ipr_origin = rpp->rp_origin;
		ipr->ipr_plen = rpp->rp_plen;
		ipr->ipr_vltime = rpp->rp_vltime;
		ipr->ipr_pltime = rpp->rp_pltime;
		ipr->ipr_flags = rpp->rp_flags;
		ipr->ipr_prefix = rpp->rp_prefix;

		break;
	case SIOCSIFPREFIX_IN6:
		/* check if preferred lifetime > valid lifetime */
		if (ipr->ipr_pltime > ipr->ipr_vltime) {
			log(LOG_NOTICE,
			    "in6_prefix_ioctl: preferred lifetime"
			    "(%ld) is greater than valid lifetime(%ld)\n",
			    (u_long)ipr->ipr_pltime, (u_long)ipr->ipr_vltime);
			error = EINVAL;
			break;
		}

		/* init rp_tmp */
		bzero((caddr_t)&rp_tmp, sizeof(rp_tmp));
		rp_tmp.rp_ifp = ifp;
		rp_tmp.rp_plen = ipr->ipr_plen;
		rp_tmp.rp_prefix = ipr->ipr_prefix;
		rp_tmp.rp_vltime = ipr->ipr_vltime;
		rp_tmp.rp_pltime = ipr->ipr_pltime;
		rp_tmp.rp_flags = ipr->ipr_flags;
		rp_tmp.rp_origin = ipr->ipr_origin;

		/* create rp_addr entries, usually at least for lladdr */
		if ((error = link_stray_ia6s(&rp_tmp)) != 0) {
			free_rp_entries(&rp_tmp);
			break;
		}
		ifnet_lock_exclusive(ifp);
		for (ifa = ifp->if_addrlist.tqh_first;
		     ifa;
		     ifa = ifa->ifa_list.tqe_next)
		{
			if (ifa->ifa_addr == NULL)
				continue;	/* just for safety */
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(IFA_IN6(ifa)) == 0)
				continue;

			if ((error = create_ra_entry(&rap)) != 0) {
				free_rp_entries(&rp_tmp);
				goto bad;
			}
			/* copy interface id part */
			bit_copy((caddr_t)&rap->ra_ifid,
				 sizeof(rap->ra_ifid) << 3,
				 (caddr_t)IFA_IN6(ifa),
				 sizeof(*IFA_IN6(ifa)) << 3,
				 rp_tmp.rp_plen,
				 (sizeof(rap->ra_ifid) << 3) - rp_tmp.rp_plen);
			/* insert into list */
			lck_mtx_lock(prefix6_mutex);
			LIST_INSERT_HEAD(&rp_tmp.rp_addrhead, rap, ra_entry);
			lck_mtx_unlock(prefix6_mutex);
		}
		ifnet_lock_done(ifp);

		error = add_each_prefix(so, &rp_tmp);

		/* free each rp_addr entry */
		free_rp_entries(&rp_tmp);

		break;
	case SIOCDIFPREFIX_IN6:
		rpp = search_matched_prefix(ifp, ipr);
		if (rpp == NULL || ifp != rpp->rp_ifp)
			return (EADDRNOTAVAIL);

		ifnet_lock_exclusive(ifp);
		error = delete_each_prefix(rpp, ipr->ipr_origin);
		ifnet_lock_done(ifp);
		break;
	}
 bad:
	return error;
}

void
in6_rr_timer(void *ignored_arg)
{
	struct rr_prefix *rpp;
	struct timeval timenow;

	getmicrotime(&timenow);

	/* expire */
	lck_mtx_lock(prefix6_mutex);
	rpp = LIST_FIRST(&rr_prefix);
	while (rpp) {
		if (rpp->rp_expire && rpp->rp_expire < timenow.tv_sec) {
			struct rr_prefix *next_rpp;

			next_rpp = LIST_NEXT(rpp, rp_entry);
			delete_each_prefix(rpp, PR_ORIG_KERNEL);
			rpp = next_rpp;
			continue;
		}
		if (rpp->rp_preferred && rpp->rp_preferred < timenow.tv_sec)
			unprefer_prefix(rpp);
		rpp = LIST_NEXT(rpp, rp_entry);
	}
	lck_mtx_unlock(prefix6_mutex);
	timeout(in6_rr_timer, (caddr_t)0, ip6_rr_prune * hz);
}
