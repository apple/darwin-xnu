/*	$KAME: mip6_md.c,v 1.14 2000/03/25 07:23:53 sumikawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999 and 2000 WIDE Project.
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
 * Copyright (c) 1999 and 2000 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Author:  Mattias Pettersson <mattias.pettersson@era.ericsson.se>
 *
 */

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#endif

/*
 * Mobile IPv6 Movement Detection for Mobile Nodes
 */
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/protosw.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/nd6.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
#include <netinet/in_pcb.h>
#endif
#include <netinet6/in6_pcb.h>
#include <netinet6/mip6.h>

#include <net/net_osdep.h>

struct nd_prefix	*mip6_home_prefix;
struct nd_prefix	*mip6_primary_prefix;
struct in6_addr		mip6_primary_defrtr;
int             	mip6_md_state = MIP6_MD_UNDEFINED;
/*
 *  Mobile IPv6 Home Address route state for the Mobile Node.
 *    route_state NET == MD_HOME == network route.
 *    route_state HOST == MD_FOREIGN|UNDEFINED == host route.
 */
int mip6_route_state = MIP6_ROUTE_NET; /* According to MD_UNDEFINED state. */
int mip6_max_lost_advints = MIP6_MAX_LOST_ADVINTS;
int mip6_nd6_delay = 0;
int mip6_nd6_umaxtries = 0;


/*
 ******************************************************************************
 * Function:    mip6_tell_em
 * Description: Print state change and tell event-state machine.
 * Ret value:   -
 ******************************************************************************
 */
static void
mip6_tell_em(int state,
	     struct nd_prefix *hp,
	     struct nd_prefix *pp,
	     struct nd_defrouter *dr)
{
#if MIP6_DEBUG
	mip6_debug("\nNew state: ");
	switch (state) {
		case MIP6_MD_HOME:
			mip6_debug("HOME!\n");
			break;
		case MIP6_MD_FOREIGN:
			mip6_debug("FOREIGN!\n");
			break;
		case MIP6_MD_UNDEFINED:
			mip6_debug("UNDEFINED!\n");
			break;
	}
	mip6_debug("Home Prefix    = %s\n", hp ? ip6_sprintf(
		&hp->ndpr_prefix.sin6_addr) : "NULL");
	mip6_debug("Primary Prefix = %s\n", pp ? ip6_sprintf(
		&pp->ndpr_prefix.sin6_addr) : "NULL");
	mip6_debug("Default Router = %s\n", dr ? ip6_sprintf(
		&dr->rtaddr) : "NULL");
#endif
	mip6_new_defrtr(state, hp, pp, dr);
}


/*
 ******************************************************************************
 * Function:    mip6_md_init
 * Description: Scan through the Event-State Machine List.
 *              Create a Home Prefix and a Home Address for the Mobile Node
 *              and add it to the prefix list (or just update it if the prefix
 *              is already existing). Detect which initial Movement Detection
 *              state we are in (HOME, FOREIGN or UNDEFINED) and tell the
 *              event-state machine.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_md_init()
{
	struct nd_prefix      *pr, *existing_pr = NULL;
	struct nd_defrouter   *dr;
	struct in6_ifaddr     *ia;
	struct mip6_esm       *esp; /* Entry in the Event State machine list */
	int                     i, s, error;

	for (esp = mip6_esmq; esp; esp = esp->next) {

	/*
	 * Add the home prefix statically to the prefix list.
	 * Code taken from prelist_update(), prelist_add() and
	 * in6_ifadd().
	 */
	pr = (struct nd_prefix *)MALLOC(sizeof(*pr), M_TEMP, M_WAITOK);
	if (pr == NULL) {
		log(LOG_ERR, "mip6_md_init: no mem for home prefix\n");
	} else {
		bzero(pr, sizeof(*pr));

		pr->ndpr_ifp = esp->ifp;
		pr->ndpr_plen = esp->prefix_len;

		pr->ndpr_prefix.sin6_family = AF_INET6;
		pr->ndpr_prefix.sin6_len = sizeof(pr->ndpr_prefix);
		pr->ndpr_prefix.sin6_addr = esp->home_addr;
		in6_prefixlen2mask(&pr->ndpr_mask, pr->ndpr_plen);

		/* make prefix in the canonical form */
		for (i = 0; i < 4; i++)
			pr->ndpr_prefix.sin6_addr.s6_addr32[i] &=
				pr->ndpr_mask.s6_addr32[i];

		/* TODO: link into interface prefix list */

		/* Default settings for unadvertised home prefix */
		pr->ndpr_raf_onlink = 0;
		pr->ndpr_raf_auto = 0;

		/*
		 * If home prefix already exists in prefix list, use that
		 * entry instead.
		 */
		if ( (existing_pr = prefix_lookup(pr)) ) {
			_FREE(pr, M_TEMP);
			pr = existing_pr;
		}

		/* Update (or set) certain fields in the home prefix */
		pr->ndpr_vltime = ND6_INFINITE_LIFETIME;
		pr->ndpr_pltime = ND6_INFINITE_LIFETIME;

		if (in6_init_prefix_ltimes(pr)) {
			log(LOG_ERR, "mip6_md_init: bad lifetimes\n");
			goto failure;
		}


		s = splnet();  /* Must be before goto statement */

		if (existing_pr != NULL) {
#if MIP6_DEBUG
			mip6_debug("mip6_md_init: Home prefix already exists, "
				   "no need to create new prefix.\n");
#endif
			goto skip_initialization;
		}

		/* New prefix, fix all initialization. */

		pr->ndpr_statef_onlink = 0; /* Should be 0 since there
					       are no adv rtrs for
					       this pfx yet */
		LIST_INIT(&pr->ndpr_advrtrs);

	  skip_initialization:

		/* If an autoconfigured address exists for pr, delete it */
		if (existing_pr != NULL) {
			if (!IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr)) {
				ia = in6ifa_ifpwithaddr(pr->ndpr_ifp,
							&pr->ndpr_addr);
				if (ia) {
					error = mip6_delete_ifaddr(
						&ia->ia_addr.sin6_addr,
						pr->ndpr_ifp);
					if (error)
						printf("%s: address assignment"
						       " error "
						       "(errno = %d).\n",
						       __FUNCTION__, error);
				}
			}
		}

		pr->ndpr_addr = esp->home_addr;

		if (existing_pr == NULL) {
			/* link ndpr_entry to nd_prefix list */
			LIST_INSERT_HEAD(&nd_prefix, pr, ndpr_entry);
		}

		splx(s);
	}
	if (esp != mip6_esmq) {
#if MIP6_DEBUG
		mip6_debug("%s: Only supporting one home address in this "
			   "version.\n", __FUNCTION__);
#endif
	}
	mip6_home_prefix = pr;

	dr = TAILQ_FIRST(&nd_defrouter);
/* XXXYYY Add check for probably reachable router here as well. Mattias */
	if (pr->ndpr_advrtrs.lh_first && dr &&
	    pfxrtr_lookup(pr, dr)) {
		/* If we have home pfxrtrs and defrtr is one of these, then
		   we're home. */
		mip6_md_state = MIP6_MD_HOME;
		/* XXX BUG ALERT: missing curly brace? */
		if ((error = mip6_add_ifaddr(&pr->ndpr_addr, pr->ndpr_ifp, 64,
					     IN6_IFF_NODAD)) != 0)
			printf("%s: address assignment error (errno = %d).\n",
			       __FUNCTION__, error);
		mip6_route_state = MIP6_ROUTE_NET;
		mip6_primary_prefix = mip6_home_prefix;
		mip6_primary_defrtr = dr->rtaddr;

		mip6_tell_em(MIP6_MD_HOME, mip6_home_prefix, NULL, dr);
	}
	else {
		if (dr) {
			mip6_md_state = MIP6_MD_FOREIGN;
			if ((error = mip6_add_ifaddr(
				&pr->ndpr_addr, pr->ndpr_ifp, 128,
				IN6_IFF_NODAD)) != 0)
				printf("%s: address assignment error "
				       "(errno = %d).\n",
				       __FUNCTION__, error);
			mip6_route_state = MIP6_ROUTE_HOST;

			for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
				if ((pfxrtr_lookup(pr, dr) != NULL) &&
				    !IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr)&&
				    !IN6_IS_ADDR_MULTICAST(&pr->ndpr_addr) &&
				    !IN6_IS_ADDR_LINKLOCAL(&pr->ndpr_addr)) {
					break;
				}
			}
			if (pr) {
				mip6_primary_prefix = pr;
				mip6_primary_defrtr = dr->rtaddr;
				mip6_tell_em(MIP6_MD_FOREIGN, mip6_home_prefix,
					     pr, dr);
			}
			else {
#if MIP6_DEBUG
				mip6_debug("%s: At FOREIGN, but no primary "
					   "prefix found!\n", __FUNCTION__);
#endif
				goto undefined;
			}
		}
		else {
		  undefined:
			mip6_md_state = MIP6_MD_UNDEFINED;
			if ((error = mip6_add_ifaddr(&pr->ndpr_addr,
						     pr->ndpr_ifp, 64,
						     IN6_IFF_NODAD)) != 0)
				printf("%s: address assignment error "
				       "(errno = %d).\n", __FUNCTION__, error);
			mip6_route_state = MIP6_ROUTE_NET;
			mip6_primary_defrtr = in6addr_any;
			mip6_primary_prefix = NULL;

			mip6_tell_em(MIP6_MD_UNDEFINED, mip6_home_prefix,
				     NULL, NULL);
		}
	}
	  failure:
	}
}


/*
 ******************************************************************************
 * Function:    mip6_select_defrtr
 * Description: Usually called as an extension to defrtrlist_del() when the
 *              previous primary default router times out. Tries to select a
 *              new default router that announces the Home Prefix if available.
 *              Manages the Movement Detection state transitions and
 *              reconfigures the Home Address with host or network route.
 *              Finally informs the event-state machine about any transitions
 *              and new default routers.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_select_defrtr()
{
	struct nd_prefix	*pr = NULL/*, *prev_primary_prefix*/;
	struct nd_defrouter	*dr, anydr;
	struct nd_pfxrouter	*pfxrtr;
	struct rtentry		*rt = NULL;
	struct llinfo_nd6	*ln = NULL;
	int			s = splnet(), error, state;

	pr = mip6_primary_prefix;
	/* Only for sanity check */
	dr = mip6_primary_prefix ?
		defrouter_lookup(&mip6_primary_defrtr,
				 mip6_primary_prefix->ndpr_ifp) : NULL;
	state = mip6_md_state;

#if MIP6_DEBUG
	mip6_debug("\n");
#endif
#if MIP6_DEBUG
	mip6_debug("%s: previous primary dr = %s.\n", __FUNCTION__,
		   ip6_sprintf(&mip6_primary_defrtr));
	mip6_debug("%s: dr = %s.\n", __FUNCTION__,
		   dr ? ip6_sprintf(&dr->rtaddr) : "NULL");
#endif

	if ( (mip6_md_state == MIP6_MD_HOME) ||
	     (mip6_md_state == MIP6_MD_UNDEFINED) ) {
		if ((pr = mip6_home_prefix) == NULL){
			log(LOG_ERR, "mip6_select_defrtr: no home prefix\n");
			splx(s);
			return;
		}

		if ((pfxrtr = find_pfxlist_reachable_router(pr)) != NULL) {
#if MIP6_DEBUG
			mip6_debug("%s: there are (reachable) pfxrtrs at "
				   "home.\n", __FUNCTION__);
#endif
			if (!IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr) &&
				!(IN6_IS_ADDR_MULTICAST(&pr->ndpr_addr) ||
				  IN6_IS_ADDR_LINKLOCAL(&pr->ndpr_addr))) {

				/* Pick first reachable pfxrtr. */
				state = MIP6_MD_HOME;

				dr = pfxrtr->router;

				/* Place dr first since its prim. */
				TAILQ_REMOVE(&nd_defrouter, dr, dr_entry);
				TAILQ_INSERT_HEAD(&nd_defrouter, dr, dr_entry);

#if MIP6_DEBUG
				mip6_debug("%s: picking %s as default router "
					   "on home subnet.\n",
					   __FUNCTION__,
					   ip6_sprintf(&(dr->rtaddr)));
#endif
				goto found;
			}
		}

		if (pr->ndpr_advrtrs.lh_first == NULL) {
#if MIP6_DEBUG
			mip6_debug("%s: there are no pfxrtrs at home, trying "
				   "non-home instead.\n", __FUNCTION__);
#endif
		}

		/*
		 * No home prefix defrtr found, just drop through and pick
		 * one by the ordinary procedure below.
		 */
#if MIP6_DEBUG
		mip6_debug("%s: no home prefix router found.\n", __FUNCTION__);
#endif
	}

	/*
	 * Go through the Default Router List in search for a (probably)
	 * reachable router that advertises a prefix and with an associated
	 * Care-of Address. This is a merge from defrouter_select().
	 */
  	if (TAILQ_FIRST(&nd_defrouter)) {
		for (dr = TAILQ_FIRST(&nd_defrouter); dr;
		     dr = TAILQ_NEXT(dr, dr_entry)) {

			if ((rt = nd6_lookup(&dr->rtaddr, 0, dr->ifp)) &&
			    (ln = (struct llinfo_nd6 *)rt->rt_llinfo) &&
			    ND6_IS_LLINFO_PROBREACH(ln)) {

				/*
				 * Find a Care-of Address from a prefix
				 * announced by this router.
				 */
				for (pr = nd_prefix.lh_first; pr;
				     pr = pr->ndpr_next) {
					if ((pfxrtr_lookup(pr, dr) != NULL) &&
					    !IN6_IS_ADDR_UNSPECIFIED(
						    &pr->ndpr_addr) &&
					    !IN6_IS_ADDR_MULTICAST(
						    &pr->ndpr_addr) &&
					    !IN6_IS_ADDR_LINKLOCAL(
						    &pr->ndpr_addr)) {
						state = MIP6_MD_FOREIGN;

#if MIP6_DEBUG
						mip6_debug("%s: new probably reachable defrtr %s on foreign subnet selected.\n", __FUNCTION__, ip6_sprintf(&dr->rtaddr));
#endif

						/*
						 * Place dr first since
						 * its prim.
						 */
						TAILQ_REMOVE(&nd_defrouter,
							     dr, dr_entry);
						TAILQ_INSERT_HEAD(
							&nd_defrouter,
							dr, dr_entry);

						goto found;
					}
				}
			}
		}

	/*
	 * No (probably) reachable router found that matched our requirements.
	 * Go through the Default Router List again in search for any
	 * router that advertises a prefix and with an associated
	 * Care-of Address. This is a merge from defrouter_select().
	 */
		for(dr = TAILQ_FIRST(&nd_defrouter); dr; dr = TAILQ_NEXT(dr, dr_entry)){
			/*
			 * Find a Care-of Address from a prefix announced by
			 * this router.
			 */
			for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
				if ((pfxrtr_lookup(pr, dr) != NULL) &&
				    !IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr)&&
				    !IN6_IS_ADDR_MULTICAST(&pr->ndpr_addr) &&
				    !IN6_IS_ADDR_LINKLOCAL(&pr->ndpr_addr)) {
					state = MIP6_MD_FOREIGN;

#if MIP6_DEBUG
					mip6_debug("%s: new (unreachable?) "
						   "defrtr %s on foreign subnet "
						   "selected.\n", __FUNCTION__,
						   ip6_sprintf(&dr->rtaddr));
#endif

					/* Place dr first since its prim. */
					TAILQ_REMOVE(&nd_defrouter, dr,
						     dr_entry);
					TAILQ_INSERT_HEAD(&nd_defrouter, dr,
							  dr_entry);
					goto found;
				}
			}
		}
	}

	/*
	 * No new defrtr or no with an associated Care-of Address found
	 * -> State = undefined
	 */
	pr = NULL;
	dr = NULL;
	state = MIP6_MD_UNDEFINED;
#if MIP6_DEBUG
	mip6_debug("%s: no new good defrtr found.\n", __FUNCTION__);
#endif

  found:
	/* XXXYYY Hope this merge is correct now... Fingers crossed. Mattias */
#if MIP6_DEBUG
	mip6_debug("%s: found: dr = %s.\n", __FUNCTION__, dr ? ip6_sprintf(&dr->rtaddr) : "NULL");
#endif
	if ((dr = TAILQ_FIRST(&nd_defrouter)) != NULL) {
#if MIP6_DEBUG
		mip6_debug("%s: TAILQ: dr = %s.\n", __FUNCTION__, dr ? ip6_sprintf(&dr->rtaddr) : "NULL");
#endif
		/*
		 * De-install the previous default gateway and install
		 * a new one.
		 * Note that if there is no reachable router in the list,
		 * the head entry will be used anyway.
		 * XXX: do we have to check the current routing table entry?
		 */
		bzero(&anydr, sizeof(anydr));
		defrouter_delreq(&anydr, 0);
		defrouter_addreq(dr);
	}
	else {
		/*
		 * The Default Router List is empty, so install the default
		 * route to an inteface.
		 * XXX: The specification does not say this mechanism should
		 * be restricted to hosts, but this would be not useful
		 * (even harmful) for routers.
		 */
		if (!ip6_forwarding) {
			/*
			 * De-install the current default route
			 * in advance.
			 */
			bzero(&anydr, sizeof(anydr));
			defrouter_delreq(&anydr, 0);
			if (nd6_defifp) {
				/*
				 * Install a route to the default interface
				 * as default route.
				 */
				defrouter_addifreq(nd6_defifp);
			}
			else	/* noisy log? */
				log(LOG_INFO, "defrouter_select: "
				    "there's no default router and no default"
				    " interface\n");
		}
	}


	/*
	 * If we grab a (unreachable) defrouter that actually is a home
	 * prefix router, we should consider ourself at home rather than
	 * default foreign.
	 */
	if (dr) {
		struct nd_pfxrouter *pfxrtr;

		pfxrtr = pfxrtr_lookup(mip6_home_prefix, dr);
		if (pfxrtr && dr == pfxrtr->router) {
#if MIP6_DEBUG
			mip6_debug("%s: dr = %s is obviously a home pfxrtr.\n", __FUNCTION__, dr ? ip6_sprintf(&dr->rtaddr) : "NULL");
#endif
			state = MIP6_MD_HOME;
			pr = mip6_home_prefix;
		}
	}

	/*
	 * First case: same router as last time.
	 * Second case: coming from UNDEFINED, we might have had a router, but
	 * we didn't have a care-of address.
	 */
	if (IN6_ARE_ADDR_EQUAL(&mip6_primary_defrtr,
			       (dr ? &dr->rtaddr : &in6addr_any)) &&
	    !(dr && mip6_primary_prefix == NULL)) {
#if MIP6_DEBUG
		mip6_debug("%s: Warning: Primary default router hasn't "
			   "changed! No action taken.\n", __FUNCTION__);
#endif
		return;
	}

	/*
	 * Switch between network and host route for the Home Address
	 * in the following cases:
	 *
	 * md_state                route_state
	 *
	 * HOME -> FOREIGN         NET -> HOST
	 * UNDEFINED -> FOREIGN    NET -> HOST
	 * FOREIGN -> HOME         HOST -> NET
	 * FOREIGN -> UNDEFINED    HOST -> NET
	 */

	if ((state == MIP6_MD_HOME || state == MIP6_MD_UNDEFINED)
	    && mip6_route_state == MIP6_ROUTE_HOST) {
		error = mip6_add_ifaddr(&mip6_home_prefix->ndpr_addr,
					mip6_home_prefix->ndpr_ifp, 64,
					IN6_IFF_NODAD);
		if (error)
			printf("%s: address assignment error (errno = %d).\n",
			       __FUNCTION__, error);
		mip6_route_state = MIP6_ROUTE_NET;
	}
	else if (state == MIP6_MD_FOREIGN &&
		 mip6_route_state == MIP6_ROUTE_NET) {
		error = mip6_add_ifaddr(&mip6_home_prefix->ndpr_addr,
					mip6_home_prefix->ndpr_ifp, 128,
					IN6_IFF_NODAD);
		if (error)
			printf("%s: address assignment error (errno = %d).\n",
			       __FUNCTION__, error);
		mip6_route_state = MIP6_ROUTE_HOST;
	}

	/*
	 * If the Mobile Node has changed its primary prefix (probably due to
	 * a move to a different subnet), clear the Neighbor Cache from entries
	 * cloned from the previous primary prefix. This does not happen when
	 * we keep the same prefix but change default router.
	 */
#if MIP6_DEBUG
	mip6_debug("mip6_primary_prefix = %s\n", mip6_primary_prefix ? ip6_sprintf(&mip6_primary_prefix->ndpr_prefix.sin6_addr) : "NULL");
	mip6_debug("pr                  = %s\n", pr ? ip6_sprintf(&pr->ndpr_prefix.sin6_addr) : "NULL");
#endif
	if (mip6_primary_prefix && (pr != mip6_primary_prefix)) {
		register struct llinfo_nd6 *ln;

		/* Taken from nd6_timer() */
		ln = llinfo_nd6.ln_next;
		/* XXX BSD/OS separates this code -- itojun */
		while (ln && ln != &llinfo_nd6) {
			struct rtentry *rt;
			struct ifnet *ifp;
			struct sockaddr_in6 *dst;
			struct llinfo_nd6 *next = ln->ln_next;

			if ((rt = ln->ln_rt) == NULL) {
				ln = next;
				continue;
			}
			if ((ifp = rt->rt_ifp) == NULL) {
				ln = next;
				continue;
			}
			dst = (struct sockaddr_in6 *)rt_key(rt);
			/* sanity check */
			if (!rt)
				panic("rt=0 in %s(ln=%p)\n", __FUNCTION__, ln);
			if (!dst)
				panic("dst=0 in %s(ln=%p)\n", __FUNCTION__, ln);

			/* Skip if the address belongs to us */
			if (ln->ln_expire == 0) {
				ln = next;
				continue;
			}

#if MIP6_DEBUG
			mip6_debug("Checking neighbor %s\n", dst ? ip6_sprintf(&dst->sin6_addr) : "NULL");
#endif
			if (in6_are_prefix_equal(&dst->sin6_addr,
						 &mip6_primary_prefix->
						 ndpr_prefix.sin6_addr,
						 mip6_primary_prefix->
						 ndpr_plen)) {

			/* Fake an INCOMPLETE neighbor that we're giving up */
				struct mbuf *m = ln->ln_hold;
				if (m) {
					m_freem(m);
				}
				ln->ln_hold = NULL;

#if MIP6_DEBUG
				mip6_debug("Deleting Neighbor %s.\n",
					   ip6_sprintf(&(satosin6(
						   rt_key(rt))->sin6_addr)));
#endif

#if IPSEC
#ifndef __OpenBSD__
				key_sa_routechange(rt_key(rt));
#endif
#endif

#if MIP6_DEBUG
				mip6_debug("Ref count = %d, now pfctlinput\n",
					   rt->rt_refcnt);
#endif

				/* New era */
				pfctlinput(PRC_REDIRECT_HOST, rt_key(rt));

#if 0
#if MIP6_DEBUG
				mip6_debug("Ref count = %d, now rt_mip6msg\n",
					   rt->rt_refcnt);
#endif

				rt_mip6msg(RTM_DELETE, ifp, rt); /* Useless? */
#endif /* 0 */
#if MIP6_DEBUG
				mip6_debug("Ref count = %d, now RTM_DELETE\n",
					   rt->rt_refcnt);
#endif
				nd6_free(rt);
			}
			ln = next;
			/*
			 * XXX Also remove the link-local addresses which
			 * aren't ours?
			 */
		}

		ln = llinfo_nd6.ln_next;
		while (ln && ln != &llinfo_nd6) {
			struct rtentry *rt;
			struct ifnet *ifp;
			struct sockaddr_dl *sdl;
			struct sockaddr_in6 *dst;
			struct llinfo_nd6 *next = ln->ln_next;

			if ((rt = ln->ln_rt) == NULL) {
				ln = next;
				continue;
			}
			if ((ifp = rt->rt_ifp) == NULL) {
				ln = next;
				continue;
			}
			dst = (struct sockaddr_in6 *)rt_key(rt);
			/* sanity check */
			if (!rt)
				panic("rt=0 in %s(ln=%p)\n", __FUNCTION__, ln);
			if (!dst)
				panic("dst=0 in %s(ln=%p)\n", __FUNCTION__, ln);

			/* Skip if the address belongs to us */
			if (ln->ln_expire == 0) {
				ln = next;
				continue;
			}

#if MIP6_DEBUG
			mip6_debug("Checking neighbor %s round 2\n", dst ? ip6_sprintf(&dst->sin6_addr) : "NULL");
#endif
			if (in6_are_prefix_equal(&dst->sin6_addr,
						 &mip6_primary_prefix->
						 ndpr_prefix.sin6_addr,
						 mip6_primary_prefix->
						 ndpr_plen)) {

#if MIP6_DEBUG
				mip6_debug("Deleting Neighbor %s round 2.\n",
					   ip6_sprintf(&(satosin6(
						   rt_key(rt))->sin6_addr)));
#endif

#if MIP6_DEBUG
				mip6_debug("Ref count = %d, now RTM_DELETE\n",
					   rt->rt_refcnt);
#endif
				if (rt && rt->rt_gateway &&
				    rt->rt_gateway->sa_family == AF_LINK) {
					sdl = (struct sockaddr_dl *)rt->
						rt_gateway;
					rtrequest(RTM_DELETE, rt_key(rt),
						  (struct sockaddr *)0,
						  rt_mask(rt), 0,
						  (struct rtentry **)0);
				}
			}
			ln = next;
			/*
			 * XXX Also remove the link-local addresses which
			 * aren't ours?
			 */
		}
	}

	/*
	 * Make decision permanent.
	 * Primary Default Router is already set above.
	 */
	mip6_md_state = state;
	mip6_primary_prefix = pr;	/* Other depend on this */
	/*
	 * Save rtaddr for next mip6_select_defrtr session.
	 */
	mip6_primary_defrtr = dr ? dr->rtaddr : in6addr_any;

	/*
	 * Assumptions made below:
	 *  - dr is the chosen Default Router
	 *  - pr is the new Primary Prefix if we're not home
	 */
	switch (mip6_md_state) {
	case MIP6_MD_HOME:
		mip6_tell_em(mip6_md_state, mip6_home_prefix, NULL, dr);
		break;

	case MIP6_MD_FOREIGN:
		mip6_tell_em(mip6_md_state, mip6_home_prefix, pr, dr);
		break;
	case MIP6_MD_UNDEFINED:
		/*
		 * Note: we pass dr == NULL, but we might have a Default
		 * Router anyway, but with no prefix/Care-of Address
		 * associated.
		 */
		mip6_tell_em(mip6_md_state, mip6_home_prefix, NULL, NULL);
		break;
	}
	splx(s);
	return;
}


/*
 ******************************************************************************
 * Function:    mip6_prelist_update(pr, dr)
 * Description: A hook to ND's prelist_update(). Checks if the Home Prefix
 *              was announced and in that case tries to force the Mobile Node
 *              to select that default router. If the Mobile Node was in
 *              UNDEFINED state we want to select that router immediately, no
 *              matter what the prefix was.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_prelist_update(pr, dr)
	struct nd_prefix    *pr;
	struct nd_defrouter *dr;
{
	if (dr == NULL) {
		return;
	}
	if (pr == mip6_home_prefix) {
		/* It was the Home Prefix that was advertised. */

		if (mip6_md_state != MIP6_MD_HOME) {
			/*
			 * We're not home but here's a router advertising
			 * our home prefix => make it primary defrtr and
			 * we're home!
			 */
#if MIP6_DEBUG
			mip6_debug("%s: returning home.\n", __FUNCTION__);
#endif
			mip6_md_state = MIP6_MD_HOME;

			/* State must be home before call. */
			if (TAILQ_FIRST(&nd_defrouter) != NULL) {
				defrouter_select();
			}
			else {
#if MIP6_DEBUG
				mip6_debug("%s: Undef -> Home: no previous "
					   "router available "
					   "at this stage.\n", __FUNCTION__);
#endif
				/* XXXYYY or use defrouter_select()? */
				mip6_select_defrtr();
			}
		}
	}
	else if (mip6_md_state == MIP6_MD_UNDEFINED) {
		/*
		 * Take care of transitions from UNDEFINED to FOREIGN, when the
		 * prefix is already known.
		 */
		if (TAILQ_FIRST(&nd_defrouter) != NULL) {
			defrouter_select();
		}
		else {
#if MIP6_DEBUG
			mip6_debug("%s: Strange, no default router available"
				   "at this stage.\n", __FUNCTION__);
#endif
			/* XXXYYY or use defrouter_select()? */
			mip6_select_defrtr();
		}
	}
}


/*
 ******************************************************************************
 * Function:    mip6_eager_md()
 * Description: If eager Movement Detection is chosen, trim parameters to a
 *              really fast hand-off. The disadvantage is that the detection
 *              becomes very exposed to go into state UNDEFINED if one single
 *              packet is lost.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_eager_md(int enable)
{
	mip6_config.eager_md = enable;
	if (enable) {
		mip6_max_lost_advints = 1;		/* Aggressive values */
		if (!mip6_nd6_delay) {
			mip6_nd6_delay = nd6_delay;		/* Store */
			mip6_nd6_umaxtries = nd6_umaxtries;	/* Store */
		}
		nd6_delay = 1;				/* Aggressive values */
		nd6_umaxtries = 1;
	}
	else {
		mip6_max_lost_advints = MIP6_MAX_LOST_ADVINTS;
		if (mip6_nd6_delay) {
			nd6_delay = mip6_nd6_delay;		/* Restore */
			nd6_umaxtries = mip6_nd6_umaxtries;	/* Restore */
			mip6_nd6_delay = 0;
			mip6_nd6_umaxtries = 0;
		}
	}
}


/*
 ******************************************************************************
 * Function:    mip6_expired_defrouter()
 * Description: If the field advint_expire (which is parallel to field
 *              expire for router lifetime) times out, allow a small number
 *              of lost Router Advertisements before doubting if this
 *              particular default router is still reachable.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_expired_defrouter(struct nd_defrouter *dr)
{
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	long time_second = time.tv_sec;
#endif

	if (!dr)
		return;

	if (dr->advint_expire && dr->advint_expire < time_second) {
		if (++(dr->advints_lost) < mip6_max_lost_advints) {
			/* advints_lost starts at 0. max = 1 (or more). */
			dr->advint_expire = time_second + dr->advint / 1000;
#if MIP6_DEBUG
			mip6_debug("Adv Int #%d lost from router %s.\n",
				   dr->advints_lost, ip6_sprintf(&dr->rtaddr));
#endif
		}
		else {
			dr->advint_expire = 0;
#if MIP6_DEBUG
			mip6_debug("Adv Int #%d lost from router %s.\n",
				   dr->advints_lost, ip6_sprintf(&dr->rtaddr));
#endif
			mip6_probe_defrouter(dr);
		}
	}
}


/*
 ******************************************************************************
 * Function:    mip6_probe_defrouter()
 * Description: Probes a default router to see if it is still reachable.
 *              Ordinary Neigbor Discovery routines (NUD) takes care of the
 *              rest. Puts this router into ND state PROBE.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_probe_defrouter(struct nd_defrouter *dr)
{
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	long time_second = time.tv_sec;
#endif
	struct rtentry *rt;
	struct llinfo_nd6 *ln;

	if (!dr)
		return;

	if (!(rt = nd6_lookup(&dr->rtaddr, 0, NULL)))
		return;

	if ((rt->rt_flags & RTF_GATEWAY)
	    || (rt->rt_flags & RTF_LLINFO) == 0
	    || !rt->rt_llinfo
	    || !rt->rt_gateway
	    || rt->rt_gateway->sa_family != AF_LINK) {
		/* This is not a host route. */
		return;
	}

	ln = (struct llinfo_nd6 *)rt->rt_llinfo;
	if ((ln->ln_state == ND6_LLINFO_INCOMPLETE)
	    || (ln->ln_state == ND6_LLINFO_PROBE)
	    || (ln->ln_state == ND6_LLINFO_WAITDELETE)
	    || (ln->ln_state == ND6_LLINFO_NOSTATE))
		return;

	/* Force state to PROBE, simulate DELAY->PROBE */
	ln->ln_asked = 1;
	ln->ln_state = ND6_LLINFO_PROBE;
	ln->ln_expire = time_second +
		nd_ifinfo[rt->rt_ifp->if_index].retrans / 1000;
	nd6_ns_output(rt->rt_ifp, &dr->rtaddr, &dr->rtaddr,
		      ln, 0);
#if MIP6_DEBUG
	mip6_debug("Probing defrouter %s\n", ip6_sprintf(&dr->rtaddr));
#endif
}


/*
 ******************************************************************************
 * Function:    mip6_probe_pfxrtrs()
 * Description: If a new or previously detached prefix is heard, probe (NUD)
 *              all prefix routers on the current primary prefix in order to
 *              quickly detect if we have moved. This is only enabled in
 *              eager Movement Detection.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_probe_pfxrtrs()
{
	struct nd_pfxrouter *pfr;
	if (!mip6_config.eager_md)
		return;

	if (!mip6_primary_prefix)
		return;

#if MIP6_DEBUG
	mip6_debug("New or detached prefix received, probe old routers:\n");
#endif
	for (pfr = mip6_primary_prefix->ndpr_advrtrs.lh_first;
	     pfr; pfr = pfr->pfr_next) {
		mip6_probe_defrouter(pfr->router);
	}
}


/*
 ******************************************************************************
 * Function:    mip6_store_advint(ai, dr)
 * Description: If Advertisement Interval option is available in Router
 *              Advertisements, keep a timer for this expiry parallel to the
 *              ordinary Router lifetime timer.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_store_advint(struct nd_opt_advint *ai,
		  struct nd_defrouter *dr)
{
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	long time_second = time.tv_sec;
#endif

	/* Check the advertisement interval option */
	if (ai->nd_opt_int_len != 1) {
		log(LOG_INFO, "%s: bad Advertisement Interval Option "
		    "length\n", __FUNCTION__);
	}
	else if (dr) {
		dr->advint = ntohl(ai->nd_opt_int_interval); /* milliseconds */

		/* Sorry for delay between reception and this setting */
		dr->advint_expire = time_second + dr->advint / 1000;
		dr->advints_lost = 0;
	}
}


/*
 ******************************************************************************
 * Function:    mip6_delete_ifaddr
 * Description: Similar to "ifconfig <ifp> <addr> delete".
 * Ret value:   -
 ******************************************************************************
 */
int
mip6_delete_ifaddr(struct in6_addr *addr,
		   struct ifnet *ifp)
{
	struct in6_aliasreq  *ifra, dummy;
	struct sockaddr_in6 *sa6;
	struct	in6_ifaddr *ia, *oia;
	int s;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3) || defined (__APPLE__)
	struct ifaddr *ifa;
#endif

	bzero(&dummy, sizeof(dummy));
	ifra = &dummy;

	ifra->ifra_addr.sin6_len = sizeof(ifra->ifra_addr);
	ifra->ifra_addr.sin6_family = AF_INET6;
	ifra->ifra_addr.sin6_addr = *addr;

	sa6 = &ifra->ifra_addr;

	if (ifp == 0)
		return(EOPNOTSUPP);

	s = splnet();

	/*
	 * Code recycled from in6_control().
	 */

	/*
	 * Find address for this interface, if it exists.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
		if (sa6->sin6_addr.s6_addr16[1] == 0) {
				/* interface ID is not embedded by the user */
			sa6->sin6_addr.s6_addr16[1] =
				htons(ifp->if_index);
		}
		else if (sa6->sin6_addr.s6_addr16[1] !=
			 htons(ifp->if_index)) {
			splx(s);
			return(EINVAL);	/* ifid is contradict */
		}
		if (sa6->sin6_scope_id) {
			if (sa6->sin6_scope_id !=
			    (u_int32_t)ifp->if_index) {
				splx(s);
				return(EINVAL);
			}
			sa6->sin6_scope_id = 0; /* XXX: good way? */
		}
	}
 	ia = in6ifa_ifpwithaddr(ifp, &ifra->ifra_addr.sin6_addr);

	/*
	 * for IPv4, we look for existing in6_ifaddr here to allow
	 * "ifconfig if0 delete" to remove first IPv4 address on the
	 * interface.  For IPv6, as the spec allow multiple interface
	 * address from the day one, we consider "remove the first one"
	 * semantics to be not preferrable.
	 */
	if (ia == 0) {
		splx(s);
		return(EADDRNOTAVAIL);
	}
	/* FALLTHROUGH */

	if (ia == 0) {
		ia = (struct in6_ifaddr *)
			MALLOC(sizeof(*ia), M_IFADDR, M_WAITOK);
		if (ia == NULL) {
			splx(s);
			return (ENOBUFS);
		}
		bzero((caddr_t)ia, sizeof(*ia));
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
		ia->ia_ifa.ifa_dstaddr
			= (struct sockaddr *)&ia->ia_dstaddr;
		ia->ia_ifa.ifa_netmask
			= (struct sockaddr *)&ia->ia_prefixmask;

		ia->ia_ifp = ifp;
		if ((oia = in6_ifaddr) != NULL) {
			for ( ; oia->ia_next; oia = oia->ia_next)
				continue;
			oia->ia_next = ia;
		} else
			in6_ifaddr = ia;
		ia->ia_ifa.ifa_refcnt++;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3) || defined (__APPLE__)
		if ((ifa = ifp->if_addrlist) != NULL) {
			for ( ; ifa->ifa_next; ifa = ifa->ifa_next)
				continue;
			ifa->ifa_next = &ia->ia_ifa;
		} else
			ifp->if_addrlist = &ia->ia_ifa;
#else
		TAILQ_INSERT_TAIL(&ifp->if_addrlist, &ia->ia_ifa,
				  ifa_list);
#endif
		ia->ia_ifa.ifa_refcnt++;
	}

	in6_purgeaddr(&ia->ia_ifa, ifp);

	splx(s);
	return(0);
}


#if 0
/*
 ******************************************************************************
 * Function:    mip6_delete_ifaddr
 * Description: Similar to "ifconfig <ifp> <addr> delete".
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_delete_ifaddr(struct in6_addr *addr,
                   struct ifnet *ifp)
{
    struct in6_aliasreq  in6_addreq;
    int s, error = 0;

    bzero(&in6_addreq, sizeof(in6_addreq));
    in6_addreq.ifra_addr.sin6_len = sizeof(in6_addreq.ifra_addr);
    in6_addreq.ifra_addr.sin6_family = AF_INET6;
    in6_addreq.ifra_addr.sin6_addr = *addr;

    s =splnet();
    error = in6_control(NULL, SIOCDIFADDR_IN6, (caddr_t)&in6_addreq, ifp
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3) && !define (__APPLE__)
			    , NULL
#endif
			    );
    splx(s);
    if (error) {
#if MIP6_DEBUG
        mip6_debug("%s: Attempt to delete addr %s failed.\n", __FUNCTION__,
              ip6_sprintf(addr));
#endif
    }
}
#endif /* 0 */

struct nd_prefix *
mip6_get_home_prefix(void)
{
    return(mip6_home_prefix);
}


int
mip6_get_md_state(void)
{
    return(mip6_md_state);
}


/*
 ******************************************************************************
 * Function:    mip6_md_exit
 * Description: Tidy up after the Mobile IPv6 Movement Detection. This is
 *              used when releasing the kernel module. The Home Prefix is
 *              deleted (even if we're home) since it's parameters might be
 *              way wrong. The Home Address is released as well. If at home,
 *              the prefix and address will be automagically configured as
 *              specified by ND.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_md_exit()
{
	struct nd_prefix *pr;

	/*
	 * XXXYYY Should use mip6_esmq when multiple Home Addresses are
	 * supported.
	 */
	pr = mip6_home_prefix;
	if (pr && pr->ndpr_ifp && !IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr)) {
		mip6_delete_ifaddr(&pr->ndpr_addr, pr->ndpr_ifp);

		prelist_remove(pr);
		mip6_home_prefix = NULL;

#if MIP6_DEBUG
		mip6_debug("Home Prefix and Home Address removed.\n");
#endif
	}
}
