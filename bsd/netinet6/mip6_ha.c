/*	$KAME: mip6_ha.c,v 1.8 2000/03/18 03:05:40 itojun Exp $	*/

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
 * Author: Conny Larsson <conny.larsson@era.ericsson.se>
 *
 */

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#endif

/*
 * Mobile IPv6 Home Agent
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/ioccom.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/nd6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>
#include <machine/limits.h>

#include <net/net_osdep.h>

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
/* Declaration of Global variables. */
struct callout_handle  mip6_timer_ll_handle;
#endif


/*
 ##############################################################################
 #
 # INITIALIZATION AND EXIT FUNCTIONS
 # These functions are executed when the MIPv6 code is activated and de-
 # activated respectively.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_ha_init
 * Description: Initialization of MIPv6 variables that must be initialized
 *              before the HA code is executed.
 ******************************************************************************
 */
void
mip6_ha_init(void)
{
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	/* Initialize handle for timer functions. */
	callout_handle_init(&mip6_timer_ll_handle);
#endif
}



/*
 ******************************************************************************
 * Function:    mip6_ha_exit
 * Description: This function is called when the HA module is unloaded
 *              (relesed) from the kernel.
 ******************************************************************************
 */
void
mip6_ha_exit()
{
	struct mip6_link_list *llp;
	int                    s;

	/* Cancel outstanding timeout function calls. */
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	untimeout(mip6_timer_ll, (void *)NULL, mip6_timer_ll_handle);
#else
	untimeout(mip6_timer_ll, (void *)NULL);
#endif

	/* Remove each entry in every queue. */
	s = splnet();
	for (llp = mip6_llq; llp;)
		llp = mip6_ll_delete(llp);
	mip6_llq = NULL;
	splx(s);
}



/*
 ##############################################################################
 #
 # RECEIVING FUNCTIONS
 # These functions receives the incoming IPv6 packet and further processing of
 # the packet depends on the content in the packet.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_rec_raha
 * Description: Processed by a Home Agent. Includes a Router Advertisement
 *              with a H-bit set in the flags variable (checked by the calling
 *              function).
 *              A link list entry and a Home Agent List entry are created or
 *              modified if needed.
 * Ret value:   0 Everything is OK. Otherwise appropriate error code.
 ******************************************************************************
 */
int
mip6_rec_raha(m, off)
struct mbuf  *m;    /* Mbuf containing the entire IPv6 packet */
int           off;  /* Offset from start of mbuf to start of RA */
{
	struct ifnet            *ifp;   /* Receiving interface */
	struct ip6_hdr          *ip6;   /* IPv6 header */
	struct nd_router_advert *ra;    /* Router Advertisement */
	struct mip6_link_list   *llp;   /* Link list entry */
	struct mip6_ha_list     *halp;  /* Home Agent list entry */
	caddr_t  icmp6msg;              /* Copy of mbuf (consequtively) */
	char     ifname[IFNAMSIZ+1];    /* Interface name */
	int      res, s, icmp6len;

	/* Find out if the RA can be processed */
	ip6 = mtod(m, struct ip6_hdr *);
	if (ip6->ip6_hlim != 255) {
		log(LOG_INFO,
		    "%s: Invalid hlim %d in Router Advertisement\n",
		    __FUNCTION__, ip6->ip6_hlim);
		return 0;
	}

	if (!IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)) {
		log(LOG_INFO,
		    "%s: Source Address %s is not link-local\n",
		    __FUNCTION__, ip6_sprintf(&ip6->ip6_src));
		return 0;
	}

	/* Find out which interface the RA arrived at */
	ifp = m->m_pkthdr.rcvif;
	sprintf(ifname, "%s", if_name(ifp));

	llp = mip6_ll_find(ifname);
	if (llp == NULL) {
		llp = mip6_ll_create(ifname, ifp);
		if (llp == NULL)
			return ENOBUFS;
	}

	/* The mbuf data must be stored consequtively to be able to
	   cast data from it. */
	icmp6len = m->m_pkthdr.len - off;
	icmp6msg = (caddr_t)MALLOC(icmp6len, M_TEMP, M_NOWAIT);
	if (icmp6msg == NULL)
		return IPPROTO_DONE;

	m_copydata(m, off, icmp6len, icmp6msg);
	ra = (struct nd_router_advert *)icmp6msg;

	/* Find the Home Agent sending the RA and read its options.
	   This section must have high priority since the Home Agent
	   list entry lifetime is initialized to 0 and could be
	   removed by the timer function before the RA options have
	   been evaluated. */
	s = splnet();
	halp = mip6_hal_find(llp->ha_list, &ip6->ip6_src);
	if (halp == NULL) {
		halp = mip6_hal_create(&llp->ha_list, &ip6->ip6_src,
				       ntohl(ra->nd_ra_router_lifetime), 0);
		if (halp == NULL) {
			splx(s);
			return ENOBUFS;
		}
	} else {
		halp->lifetime = ntohl(ra->nd_ra_router_lifetime);
		halp->pref = 0;
	}

	res = mip6_ra_options(halp, icmp6msg, icmp6len);
	if (res) {
		splx(s);
		return res;
	}
	splx(s);
	return 0;
}



/*
 ##############################################################################
 #
 # UTILITY FUNCTIONS
 # Miscellaneous functions needed for the internal processing of incoming and
 # outgoing control signals.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_ra_options
 * Description: Search through all the options in the Router Advertisement
 *              and store them in the Home Agent List.
 * Ret value:   0 Everything is OK. Otherwise appropriate error code.
 ******************************************************************************
 */
int
mip6_ra_options(halp, icmp6msg, icmp6len)
struct mip6_ha_list  *halp;      /* Home Agent list entry */
caddr_t               icmp6msg;  /* icmp6 message */
int                   icmp6len;  /* Length of icmp6 message */
{
	struct mip6_addr_list     *ap;   /* Address list entry */
	struct nd_opt_hai         *hai;  /* Home Agent information option */
	struct nd_opt_advint      *ai;   /* Advertisement Interval option */
	struct nd_opt_prefix_info *pi;   /* Ptr to prefix information */
	u_int8_t                  *optp; /* Ptr to current option in RA */
	int       cur_off;               /* Cur offset from start of RA */

	/* Process each option in the RA */
	cur_off = sizeof(struct nd_router_advert);
	while (cur_off < icmp6len) {
		optp = ((caddr_t)icmp6msg + cur_off);
		if (*optp == ND_OPT_PREFIX_INFORMATION) {
			/* Check the prefix information option */
			pi = (struct nd_opt_prefix_info *)optp;
			if (pi->nd_opt_pi_len != 4) {
				ip6stat.ip6s_badoptions++;
				return IPPROTO_DONE;
			}

			if (!(pi->nd_opt_pi_flags_reserved &
			      ND_OPT_PI_FLAG_RTADDR)) {
				cur_off += 4 * 8;
				continue;
			}

			if (IN6_IS_ADDR_MULTICAST(&pi->nd_opt_pi_prefix) ||
			    IN6_IS_ADDR_LINKLOCAL(&pi->nd_opt_pi_prefix)) {
				cur_off += 4 * 8;
				continue;
			}

			/* Aggregatable unicast address, rfc2374 */
			if (((pi->nd_opt_pi_prefix.s6_addr8[0] & 0xe0) > 0x10)
			    && (pi->nd_opt_pi_prefix_len != 64)) {
				cur_off += 4 * 8;
				continue;
			}

			/* Store the address if not already present */
			for (ap = halp->addr_list; ap; ap = ap->next) {
				if (IN6_ARE_ADDR_EQUAL(&ap->ip6_addr,
						       &pi->nd_opt_pi_prefix))
					break;
			}

			if (ap == NULL) {
				/* Create a new address list entry. */
				ap = (struct mip6_addr_list *)
					MALLOC(sizeof(struct mip6_addr_list),
					       M_TEMP, M_WAITOK);
				if (ap == NULL)
					return ENOBUFS;
				bzero(ap, sizeof(struct mip6_addr_list));

				ap->next = halp->addr_list;
				ap->ip6_addr = pi->nd_opt_pi_prefix;
				ap->prefix_len = pi->nd_opt_pi_prefix_len;
				halp->addr_list = ap;
			}
			cur_off += 4 * 8;
			continue;
		} else if (*optp == ND_OPT_ADV_INTERVAL) {
			/* Check the advertisement interval option */
			ai = (struct nd_opt_advint *)optp;
			if (ai->nd_opt_int_len != 1) {
				ip6stat.ip6s_badoptions++;
				return IPPROTO_DONE;
			}

			/* XXX. Function call to move detection */
			cur_off += 8;
			continue;
		} else if (*optp == ND_OPT_HA_INFORMATION) {
			/* Check the home agent information option */
			hai = (struct nd_opt_hai *)optp;
			if (hai->nd_opt_hai_len != 1) {
				ip6stat.ip6s_badoptions++;
				return IPPROTO_DONE;
			}

			halp->pref = ntohs(hai->nd_opt_hai_pref);
			halp->lifetime = ntohs(hai->nd_opt_hai_lifetime);
			cur_off += 8;
			continue;
		} else {
			if (*(optp + 1) == 0) {
				ip6stat.ip6s_badoptions++;
				return IPPROTO_DONE;
			}
			cur_off += *(optp + 1) * 8;
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_hal_dynamic
 * Description: Search through all the link lists and home agents list and
 *              create a Home Agents List sub-option to be used in dynamic
 *              home agent address discovery.
 *              If my own global source address is included in the first
 *              home agents list entry, leave it. It will be in the source
 *              address of the outgoing packet anyway.
 * Ret value:   Ptr to the sub-option or NULL.
 ******************************************************************************
 */
struct mip6_subopt_hal *
mip6_hal_dynamic(own_addr)
struct in6_addr  *own_addr;   /* Own global unicast source address used */
{
    struct mip6_link_list  *llp;       /* Link list entry */
    struct mip6_ha_list    *halp;      /* Home Agent list entry */
    struct mip6_subopt_hal *opt;       /* Home Agents list sub-option */
    struct mip6_addr_list  *addrp;     /* Address list entry */
    struct mip6_addr_list  *tmp_addrp; /* Temporary address list entry */
    struct ifaddr          *if_addr;   /* Interface data */
    struct sockaddr_in6     sin6;
    char   ifname[IFNAMSIZ+1];       /* Interface name */
    int    ii, len, found;

    /* Find the interface */
    bzero(&sin6, sizeof(struct sockaddr_in6));
    sin6.sin6_len = sizeof(struct sockaddr_in6);
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = *own_addr;

    if_addr = ifa_ifwithaddr((struct sockaddr *)&sin6);
    if (if_addr == NULL)
        return NULL;

    sprintf(ifname, "%s", if_name(if_addr->ifa_ifp));

    llp = mip6_ll_find(ifname);
    if (llp == NULL)
        return NULL;

    /* Allocate memory for home agent list sub option */
    opt = (struct mip6_subopt_hal *)MALLOC(sizeof(struct mip6_subopt_hal) +
                                           31 * sizeof(struct in6_addr),
                                           M_TEMP, M_WAITOK);
    if (opt == NULL)
        return NULL;

    opt->type = IP6SUBOPT_HALIST;
    opt->len = 0;

    /* Search the home agents list for the specific link. */
    /* First, sort the Home Agent list in decending order */
    mip6_hal_sort(&llp->ha_list);
    ii = 0;
    for (halp = llp->ha_list; halp; halp = halp->next) {
        tmp_addrp = NULL;
        found = 0;
        for (addrp = halp->addr_list; addrp; addrp = addrp->next) {
            len = addrp->prefix_len;
            if (in6_are_prefix_equal(own_addr, &addrp->ip6_addr, len)) {
                if (IN6_ARE_ADDR_EQUAL(own_addr, &addrp->ip6_addr)) {
                    found = 1;
                    break;
                } else if (tmp_addrp == NULL)
                    tmp_addrp = addrp;
            }
        }

        if (found && (ii != 0)) {
            opt->halist[ii] = addrp->ip6_addr;
            opt->len += IP6OPT_HALISTLEN;
            ii += 1;
        } else if (tmp_addrp != NULL) {
            opt->halist[ii] = tmp_addrp->ip6_addr;
            opt->len += IP6OPT_HALISTLEN;
            ii += 1;
        }
    }

    if (opt->len != 0)
        return opt;
    else {
        _FREE(opt, M_TEMP);
        return NULL;
    }
}



/*
 ******************************************************************************
 * Function:    mip6_global_addr
 * Description: Search the list of IP addresses and find the interface for
 *              the anycast address. Find a link local address and use this
 *              address while searching through the list of home agents.
 *              When my own home agent is found, pick the first global address
 *              which matches the aycast prefix.
 * Ret value:   Ptr to the global unicast address or NULL.
 ******************************************************************************
 */
struct in6_addr *
mip6_global_addr(anycast_addr)
struct in6_addr  *anycast_addr;   /* Home Agents anycast address */
{
    struct in6_ifaddr     *ia;    /* I/f address for anycast address */
    struct in6_ifaddr     *ia_ll; /* I/f address for link local address */
    struct ifnet          *ifp;   /* Interface */
    struct mip6_ha_list   *halp;  /* Home Agent list entry */
    struct mip6_addr_list *addrp; /* Address list entry */
    struct mip6_link_list *llp;   /* Link list entry for anycast address */
    char   ifname[IFNAMSIZ+1];    /* Interface name */

    /* Find out the interface for the anycast address */
    for (ia = in6_ifaddr; ia; ia = ia->ia_next)
    {
        if (ia->ia_addr.sin6_family != AF_INET6)
            continue;
        if ((ia->ia6_flags & IN6_IFF_ANYCAST) &&
            IN6_ARE_ADDR_EQUAL(anycast_addr, &ia->ia_addr.sin6_addr))
            break;
    }

    if (ia == NULL)
        return NULL;

    ifp = ia->ia_ifa.ifa_ifp;
    sprintf(ifname, "%s", if_name(ifp));
    llp = mip6_ll_find(ifname);
    if (llp == NULL)
        return NULL;

    /* Use link local address to identify my own home agent list entry */
    /* XXX: I'm not sure if the 2nd arg is OK(jinmei@kame) */
    ia_ll = in6ifa_ifpforlinklocal(ifp, 0);
    if (ia_ll == NULL)
	    return NULL;
    halp = mip6_hal_find(llp->ha_list, &ia_ll->ia_addr.sin6_addr);
    if (halp == NULL)
        return NULL;

    /* Find my global address */
    for (addrp = halp->addr_list; addrp; addrp = addrp->next) {
        if (in6_are_prefix_equal(anycast_addr, &addrp->ip6_addr,
                                 addrp->prefix_len))
            return &addrp->ip6_addr;
    }
    return NULL;
}



/*
 ******************************************************************************
 * Function:    mip6_icmp6_output
 * Description: Takes care of an outgoing Router Advertisement. It finds the
 *              outgoing interface and add each prefix to the home agents list.
 *              Each prefix is also added to the internal prefix list used
 *              when a BU is received to decide whether the MN is on-link or
 *              not.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_icmp6_output(m)
struct mbuf *m;     /* Mbuf chain with IPv6 packet */
{
    struct ip6_hdr            *ip6;     /* IPv6 header */
    struct icmp6_hdr          *icmp6;   /* ICMP6 header */
    struct nd_router_advert   *ra;      /* Router Advertisement */
    struct ifaddr             *if_addr; /* Interface address */
    struct mip6_link_list     *llp;     /* Link list entry */
    struct mip6_ha_list       *halp;    /* Home Agent list entry */
    struct sockaddr_in6        sin6;
    caddr_t    icmp6msg;                /* Copy of mbuf (consequtively) */
    char       ifname[IFNAMSIZ+1];      /* Interface name */
    int        icmp6len, s, res;

    /* Check if the packet shall be processed */
    if (!MIP6_IS_HA_ACTIVE)
        return;

    ip6 = mtod(m, struct ip6_hdr *);
    if (ip6->ip6_nxt != IPPROTO_ICMPV6)
        return;

    /* The mbuf data must be stored consequtively to be able to cast data
       from it. */
    icmp6len = m->m_pkthdr.len - sizeof(struct ip6_hdr);
    icmp6msg = (caddr_t)MALLOC(icmp6len, M_TEMP, M_WAITOK);
    if (icmp6msg == NULL)
        return;

    m_copydata(m, sizeof(struct ip6_hdr), icmp6len, icmp6msg);
    icmp6 = (struct icmp6_hdr *)icmp6msg;

    /* Check if the packet shall be processed */
    if (icmp6->icmp6_type != ND_ROUTER_ADVERT) {
        _FREE(icmp6msg, M_TEMP);
        return;
    }

    if (icmp6->icmp6_code != 0) {
        _FREE(icmp6msg, M_TEMP);
        return;
    }

    if (icmp6len < sizeof(struct nd_router_advert)) {
        _FREE(icmp6msg, M_TEMP);
        return;
    }

    /* Find the outgoing interface */
    bzero(&sin6, sizeof(struct sockaddr_in6));
    sin6.sin6_len = sizeof(struct sockaddr_in6);
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = ip6->ip6_src;

    if_addr = ifa_ifwithaddr((struct sockaddr *)&sin6);
    if (if_addr == NULL) {
        _FREE(icmp6msg, M_TEMP);
        return;
    }

    sprintf(ifname, "%s", if_name(if_addr->ifa_ifp));

    llp = mip6_ll_find(ifname);
    if (llp == NULL) {
        llp = mip6_ll_create(ifname, if_addr->ifa_ifp);
        if (llp == NULL) {
            _FREE(icmp6msg, M_TEMP);
            return;
        }
    }

    /* Find the Home Agent sending the RA and read its options.
       This section must have high priority since the Home Agent list
       entry lifetime is initialized to 0 and could be removed by the
       timer function before the RA options have been evaluated. */
    s = splnet();
    ra = (struct nd_router_advert *)icmp6;
    halp = mip6_hal_find(llp->ha_list, &ip6->ip6_src);
    if (halp == NULL) {
        halp = mip6_hal_create(&llp->ha_list, &ip6->ip6_src,
                               ntohl(ra->nd_ra_router_lifetime), 0);
        if (halp == NULL) {
            _FREE(icmp6msg, M_TEMP);
            splx(s);
            return;
        }
    } else {
        halp->lifetime = ntohl(ra->nd_ra_router_lifetime);
        halp->pref = 0;
    }

    res = mip6_ra_options(halp, icmp6msg, icmp6len);
    if (res) {
        _FREE(icmp6msg, M_TEMP);
        splx(s);
        return;
    }
    splx(s);

    /* Add the prefix to prefix list and the anycast address to the
       interface. */
    mip6_prefix_examine(halp, if_addr->ifa_ifp, icmp6msg, icmp6len);
    _FREE(icmp6msg, M_TEMP);
    return;
}



/*
 ******************************************************************************
 * Function:    mip6_prefix_examine
 * Description: Add each prefix in a RA to the internal prefix list. Make
 *              sure that the Home-Agents anycast address for the prefix
 *              has been assigned to the interface.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_prefix_examine(halp, ifp, icmp6msg, icmp6len)
struct mip6_ha_list *halp;      /* Home Agent list entry */
struct ifnet        *ifp;       /* Outgoing i/f for prefixes */
caddr_t              icmp6msg;  /* icmp6 message */
int                  icmp6len;  /* Length of icmp6 message */
{
    struct nd_opt_prefix_info *pi;       /* Ptr to prefix information */
    struct mip6_prefix        *pq;       /* Prefix queue entry */
    struct in6_addr  anycast_addr;
    int              cur_off;            /* Cur offset from start of mbuf */
    u_int8_t         *opt_ptr;           /* Ptr to current option in RA */

    /* Process each option in the RA */
    cur_off = sizeof(struct nd_router_advert);
    while (cur_off < icmp6len) {
        opt_ptr = ((caddr_t)icmp6msg + cur_off);
        if (*opt_ptr == ND_OPT_PREFIX_INFORMATION) {
            /* Check the prefix information option */
            pi = (struct nd_opt_prefix_info *)opt_ptr;
            if (pi->nd_opt_pi_len != 4)
                return;

            if (!(pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK)) {
                cur_off += 4 * 8;
                continue;
            }

            if (IN6_IS_ADDR_MULTICAST(&pi->nd_opt_pi_prefix) ||
                IN6_IS_ADDR_LINKLOCAL(&pi->nd_opt_pi_prefix)) {
                cur_off += 4 * 8;
                continue;
            }

            /* Aggregatable unicast address, rfc2374 */
            if (((pi->nd_opt_pi_prefix.s6_addr8[0] & 0xe0) > 0x10) &&
                (pi->nd_opt_pi_prefix_len != 64)) {
                cur_off += 4 * 8;
                continue;
            }

            /* Store the prefix if not already present */
            pq = mip6_prefix_find(&pi->nd_opt_pi_prefix,
                                  pi->nd_opt_pi_prefix_len);
            if (pq == NULL) {
		int error;
                pq = mip6_prefix_create(ifp, &pi->nd_opt_pi_prefix,
                                        pi->nd_opt_pi_prefix_len,
                                        pi->nd_opt_pi_valid_time);
                if (pq == NULL)
                    return;

                /* Create an Home Agent anycast address, add it to the
                   interface */
                mip6_build_ha_anycast(&anycast_addr,
                                      &pi->nd_opt_pi_prefix,
                                      pi->nd_opt_pi_prefix_len);
                error = mip6_add_ifaddr(&anycast_addr, ifp,
                                        pi->nd_opt_pi_prefix_len,
                                        IN6_IFF_ANYCAST);
		if (error)
			printf("%s: address assignment error (errno = %d).\n",
			       __FUNCTION__, error);

            } else
                pq->valid_time = ntohl(pi->nd_opt_pi_valid_time);

            cur_off += 4 * 8;
            continue;
        } else {
            if (*(opt_ptr + 1) == 0) {
                return;
            }
            cur_off += *(opt_ptr + 1) * 8;
        }
    }
}



/*
 ##############################################################################
 #
 # LIST FUNCTIONS
 # The Home Agent maintains three lists (link list, home agent list and global
 # address list) which are integrated into each other. Besides from this an
 # internal prefix list is maintained in order to know which prefixes it is
 # supposed to be home network for. The functions in this section are used for
 # maintenance (create, find, delete and update entries) of these lists.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_ll_find
 * Description: For each physical interface, i.e. link, that a Home Agent
 *              send and receive Router Advertisements at, a link list entry
 *              is maintained.
 * Ret value:   Pointer to found link list entry or NULL.
 ******************************************************************************
 */
struct mip6_link_list *
mip6_ll_find(ifname)
char  *ifname;
{
    struct mip6_link_list  *llp;

    for (llp = mip6_llq; llp; llp = llp->next) {
        if (strcmp(ifname, llp->ifname) == 0)
            return llp;
    }
    return NULL;
}



/*
 ******************************************************************************
 * Function:    mip6_ll_create
 * Description: Create a new link list entry and add it first to the link
 *              list. Start the timer if not already started.
 * Ret value:   Pointer to created link list entry or NULL.
 ******************************************************************************
 */
struct mip6_link_list *
mip6_ll_create(ifname, ifp)
char         *ifname;
struct ifnet *ifp;
{
    struct mip6_link_list  *llp;
    int    s, start_timer = 0;

    if (mip6_llq == NULL)
        start_timer = 1;

    llp = (struct mip6_link_list *)MALLOC(sizeof(struct mip6_link_list),
                                          M_TEMP, M_WAITOK);
    if (llp == NULL)
        return NULL;
    bzero(llp, sizeof(struct mip6_link_list));

    /* Add the new link list entry first to the list. */
    s = splnet();
    llp->next = mip6_llq;
    strcpy(llp->ifname, ifname);
    llp->ifp = ifp;
    llp->ha_list = NULL;
    mip6_llq = llp;
    splx(s);

    if (start_timer) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
        mip6_timer_ll_handle =
#endif
        timeout(mip6_timer_ll_funneled, (void *)0, hz);
    }
    return llp;
}



/*
 ******************************************************************************
 * Function:    mip6_ll_delete
 * Description: Delete the requested link list entry.
 * Ret value:   Ptr to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
struct mip6_link_list *
mip6_ll_delete(llp_del)
struct mip6_link_list  *llp_del;    /* Link list entry to be deleted */
{
    struct mip6_link_list  *llp;       /* Current entry in the list */
    struct mip6_link_list  *llp_prev;  /* Previous entry in the list */
    struct mip6_link_list  *llp_next;  /* Next entry in the list */
    struct mip6_ha_list    *halp;      /* Home Agents list */
    int    s;

    /* Find the requested entry in the link list. */
    s = splnet();
    llp_next = NULL;
    llp_prev = NULL;
    for (llp = mip6_llq; llp; llp = llp->next) {
        llp_next = llp->next;
        if (llp == llp_del) {
            if (llp_prev == NULL)
                mip6_llq = llp->next;
            else
                llp_prev->next = llp->next;

            if (llp->ha_list) {
                for (halp = llp->ha_list; halp;)
                    halp = mip6_hal_delete(&llp->ha_list, halp);
            }

#if MIP6_DEBUG
            mip6_debug("\nLink List entry deleted (0x%x)\n", llp);
#endif
            _FREE(llp, M_TEMP);

            /* Remove the timer if the BC queue is empty */
            if (mip6_llq == NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
                untimeout(mip6_timer_ll, (void *)NULL, mip6_timer_ll_handle);
                callout_handle_init(&mip6_timer_ll_handle);
#else
                untimeout(mip6_timer_ll, (void *)NULL);
#endif
            }
            break;
        }
        llp_prev = llp;
    }
    splx(s);
    return llp_next;
}



/*
 ******************************************************************************
 * Function:    mip6_hal_find
 * Description: Find a Home Agent list entry at a specific link. There will
 *              be one entry for each node sending a Router Advertisement
 *              with the H-bit set including a Prefix Information option
 *              with the R-bit set, for which the Router lifetime or the
 *              Home Agent lifetime (included in a separate option) is not 0.
 * Ret value:   Pointer to found Home Agent list entry or NULL.
 ******************************************************************************
 */
struct mip6_ha_list *
mip6_hal_find(hal_start, ll_addr)
struct mip6_ha_list *hal_start;  /* First entry in the Home Agents list */
struct in6_addr     *ll_addr;    /* Link local address to search for */
{
    struct mip6_ha_list  *halp;

    for (halp = hal_start; halp; halp = halp->next) {
        if (IN6_ARE_ADDR_EQUAL(&halp->ll_addr, ll_addr))
            return halp;
    }
    return NULL;
}



/*
 ******************************************************************************
 * Function:    mip6_hal_create
 * Description: Create a Home Agent list entry for a specific link.
 * Ret value:   Pointer to created Home Agent list entry or NULL.
 ******************************************************************************
 */
struct mip6_ha_list *
mip6_hal_create(hal_start, ll_addr, lifetime, pref)
struct mip6_ha_list **hal_start; /* First entry in the Home Agents list */
struct in6_addr     *ll_addr;    /* Link local address to search for */
u_int32_t            lifetime;   /* Node lifetime */
int16_t              pref;       /* Node preference */
{
    struct mip6_ha_list  *halp;
    int    s;

    halp = (struct mip6_ha_list *)MALLOC(sizeof(struct mip6_ha_list),
                                         M_TEMP, M_WAITOK);
    if (halp == NULL)
        return NULL;
    bzero(halp, sizeof(struct mip6_ha_list));

    /* Add the new home agent list entry first to the list. */
    s = splnet();
    halp->next = *hal_start;
    halp->ll_addr = *ll_addr;
    halp->lifetime = lifetime;
    halp->pref = pref;
    halp->addr_list = NULL;
    *hal_start = halp;
    splx(s);
    return halp;
}



/*
 ******************************************************************************
 * Function:    mip6_hal_sort
 * Description: Sort the Home Agent list in decending order. Uses a temporary
 *              list where all the existing elements are moved.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_hal_sort(ha_head)
struct mip6_ha_list  **ha_head;  /* Start of Home Agent list */
{
    struct mip6_ha_list  *start, *halp;
    struct mip6_ha_list  *halp_prev, *halp_before, *halp_move;
    struct mip6_ha_list  *local_start, *local_last;
    int16_t last_pref;
    int     s;

    if (*ha_head == NULL)
        return;

    s = splnet();
    start = *ha_head;
    local_start = NULL;
    local_last = NULL;

    while (1) {
        /* Find entry with highest preference */
        last_pref = SHRT_MIN;
        halp_prev = NULL;
        for (halp = start; halp; halp = halp->next) {
            if (halp->pref > last_pref) {
                last_pref = halp->pref;
                halp_move = halp;
                halp_before = halp_prev;
            }
            halp_prev = halp;
        }

        /* Move it to the new list */
        if (local_start == NULL)
            local_start = halp_move;
        else
            local_last->next = halp_move;
        local_last = halp_move;

        /* Update the existing list */
        if (halp_before == NULL)
            start = halp_move->next;
        else
            halp_before->next = halp_move->next;

        if (start == NULL)
            break;
    }
    *ha_head = local_start;
    splx(s);
    return;
}



/*
 ******************************************************************************
 * Function:    mip6_hal_delete
 * Description: Delete a Home Agent list entry. If there are any address list
 *              entries associated with the Home Agent entry they are deleted
 *              as well.
 * Ret value:   Pointer to the next Home Agent list entry.
 *              NULL if the remaining list is empty or end of list reached.
 ******************************************************************************
 */
struct mip6_ha_list	*
mip6_hal_delete(ha_start, ha_delete)
struct mip6_ha_list **ha_start;  /* First list entry of HAs for a link */
struct mip6_ha_list *ha_delete;  /* Home Agent entry to delete */
{
    struct mip6_ha_list    *halp;         /* Current HA list entry */
    struct mip6_ha_list    *halp_prev;    /* Previous HA list entry */
    struct mip6_addr_list  *addrp;        /* Address list entry */
    struct mip6_addr_list  *addr_delete;  /* Address list entry to delete */
    int    s;

    s = splnet();
    halp_prev = NULL;
    for (halp = *ha_start; halp; halp = halp->next) {
        if (halp != ha_delete) {
            halp_prev = halp;
            continue;
        }

        /* Search the address list and remove each entry */
        for (addrp = halp->addr_list; addrp;) {
            addr_delete = addrp;
            addrp = addrp->next;
            _FREE(addr_delete, M_TEMP);
        }

        /* Make sure that the pointer to the first entry is correct */
        if (halp == *ha_start) {
            *ha_start = halp->next;
            _FREE(halp, M_TEMP);
            splx(s);
            return *ha_start;
        } else {
            halp_prev->next = halp->next;
            _FREE(halp, M_TEMP);
            splx(s);
            return halp_prev->next;
        }
    }
    splx(s);
    return NULL;
}



/*
 ##############################################################################
 #
 # TIMER FUNCTIONS
 # These functions are called at regular basis. They operate on the lists,
 # e.g. reducing timer counters and removing entries from the list if needed.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_timer_ll
 * Description: Search the Home Agent list for each link and delete entries for
 *              which the timer has expired.
 *              If there are more entries left in the Home Agent list, call
 *              this fuction again once every second until the list is empty.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_ll_funneled(arg)
void  *arg;  /* Not used */
{
#ifdef __APPLE__
	boolean_t   funnel_state;
    	funnel_state = thread_funnel_set(network_flock, TRUE);
#endif
	mip6_timer_ll(arg);
#ifdef __APPLE__
        (void) thread_funnel_set(network_flock, FALSE);
#endif
}
void
mip6_timer_ll(arg)
void  *arg;  /* Not used */
{
    struct mip6_link_list  *llp;        /* Current Link list entry */
    struct mip6_ha_list    *halp;       /* Current Home Agent list entry */
    int                    s;

    /* Go through the entire Home Agent List and delete all entries
       for which the time has expired. */
    s = splnet();
    for (llp = mip6_llq; llp;) {
        for (halp = llp->ha_list; halp;) {
            halp->lifetime -= 1;
            if (halp->lifetime == 0)
                halp = mip6_hal_delete(&llp->ha_list, halp);
            else
                halp = halp->next;
        }

        if (llp->ha_list == NULL)
            llp = mip6_ll_delete(llp);
        else
            llp = llp->next;
    }
    splx(s);

    if (mip6_llq != NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
        mip6_timer_ll_handle =
#endif
        timeout(mip6_timer_ll_funneled, (void *)0, hz);
    }
}



/*
 ##############################################################################
 #
 # IOCTL FUNCTIONS
 # These functions are called from mip6_ioctl.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_write_config_data_ha
 * Description: This function is called to write certain config values for
 *              MIPv6. The data is written into the global config structure.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_write_config_data_ha(u_long cmd, void *arg)
{
    int                      retval = 0;

    switch (cmd) {
        case SIOCSHAPREF_MIP6:
            mip6_config.ha_pref = ((struct mip6_input_data *)arg)->value;
            break;
    }
    return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_clear_config_data_ha
 * Description: This function is called to clear internal lists handled by
 *              MIPv6.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_clear_config_data_ha(u_long cmd, void *data)
{
    int retval = 0;
    int s;
	struct mip6_link_list   *llp;

	s = splnet();
    switch (cmd) {
        case SIOCSHALISTFLUSH_MIP6:
            for (llp = mip6_llq; llp;)
                llp = mip6_ll_delete(llp);
            break;
    }
    splx(s);
    return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_enable_func_ha
 * Description: This function is called to enable or disable certain functions
 *              in mip6. The data is written into the global config struct.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_enable_func_ha(u_long cmd, caddr_t data)
{
    int enable;
    int retval = 0;

    enable = ((struct mip6_input_data *)data)->value;

    switch (cmd) {
        case SIOCSFWDSLUNICAST_MIP6:
            mip6_config.fwd_sl_unicast = enable;
            break;

        case SIOCSFWDSLMULTICAST_MIP6:
            mip6_config.fwd_sl_multicast = enable;
            break;
    }
    return retval;
}
