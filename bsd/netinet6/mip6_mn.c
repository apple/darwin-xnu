/*	$KAME: mip6_mn.c,v 1.11 2000/03/18 03:05:42 itojun Exp $	*/

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
 * Mobile IPv6 Mobile Nodes
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
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>

/* Declaration of Global variables. */
struct mip6_bul  *mip6_bulq = NULL;  /* First entry in Binding Update list */
struct mip6_esm  *mip6_esmq = NULL;  /* List of event-state machines */

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
struct callout_handle  mip6_timer_outqueue_handle;
struct callout_handle  mip6_timer_bul_handle;
struct callout_handle  mip6_timer_esm_handle;
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
 * Function:    mip6_mn_init
 * Description: Initialization of MIPv6 variables that must be initialized
 *              before the MN code is executed.
 ******************************************************************************
 */
void
mip6_mn_init(void)
{
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	/* Initialize handle for timer functions. */
	callout_handle_init(&mip6_timer_outqueue_handle);
	callout_handle_init(&mip6_timer_bul_handle);
	callout_handle_init(&mip6_timer_esm_handle);
#endif

	printf("%s: MIP6 Mobile Node initialized\n", __FUNCTION__);
}



/*
 ******************************************************************************
 * Function:    mip6_mn_exit
 * Description: This function is called when the MN module is unloaded
 *              (relesed) from the kernel.
 ******************************************************************************
 */
void
mip6_mn_exit()
{
	struct mip6_output  *outp, *outp_tmp;
	struct mip6_bul     *bulp;
	struct mip6_esm     *esp;
	int                  s;

	/* Cancel outstanding timeout function calls. */
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	untimeout(mip6_timer_outqueue, (void *)NULL,
		  mip6_timer_outqueue_handle);
	untimeout(mip6_timer_bul, (void *)NULL, mip6_timer_bul_handle);
	untimeout(mip6_timer_esm, (void *)NULL, mip6_timer_esm_handle);
#else
	untimeout(mip6_timer_outqueue, (void *)NULL);
	untimeout(mip6_timer_bul, (void *)NULL);
	untimeout(mip6_timer_esm, (void *)NULL);
#endif

	/* Remove each entry in every queue. */
	s = splnet();
	for (outp = mip6_outq; outp;) {
		outp_tmp = outp;
		outp = outp->next;
		if (outp_tmp->opt)
			_FREE(outp_tmp->opt, M_TEMP);
		if (outp_tmp->subopt)
			_FREE(outp_tmp->subopt, M_TEMP);
		_FREE(outp_tmp, M_TEMP);
	}
	mip6_outq = NULL;

	for (bulp = mip6_bulq; bulp;)
		bulp = mip6_bul_delete(bulp);
	mip6_bulq = NULL;

	for (esp = mip6_esmq; esp;)
		esp = mip6_esm_delete(esp);
	mip6_esmq = NULL;
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
 * Function:    mip6_new_defrtr
 * Description: Called from the move detection algorithm when it has decided
 *              to change default router, i.e the network that we were
 *              connected to has changed.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_new_defrtr(state, home_prefix, prim_prefix, def_router)
int                 state;         /* State from move detection algorithm */
struct nd_prefix    *home_prefix;  /* Prefix for Home Address */
struct nd_prefix    *prim_prefix;  /* Prefix for primary care-of address */
struct nd_defrouter *def_router;   /* New default router being used */
{
	struct in6_addr     *home_addr;   /* Home Address for Mobile Node */
	struct in6_addr     *prim_addr;   /* Primary Care-of Adress for MN */
	struct mip6_esm     *esp;         /* Home address entry */
	struct mip6_bul     *bulp;        /* Entry in the BU list */
	struct ifaddr       *if_addr;     /* Interface address */
	struct mip6_bu_data  bu_data;     /* Data used when a BU is created */
	struct in6_addr      ll_all_addr; /* Link local all nodes address */
	struct in6_addr      old_coa;
	struct sockaddr_in6  sin6;
	u_int32_t            lifetime;    /* Lifetime used in BU */
	u_long               na_flags;    /* Flags for NA message */

	/* Check incoming parameters */
	if (home_prefix != NULL)
		home_addr = &home_prefix->ndpr_addr;
	else {
		log(LOG_ERR, "%s: No home address configured\n", __FUNCTION__);
		return;
	}

	esp = mip6_esm_find(home_addr);
	if (esp == NULL) {
		log(LOG_ERR,
		    "%s: No event-state machine found\n", __FUNCTION__);
		return;
	}

	if (prim_prefix != NULL)
		prim_addr = &prim_prefix->ndpr_addr;
	else
		prim_addr = NULL;

	/* Decide how the mobile node has moved. */
	if ((prim_prefix == NULL) && (state == MIP6_MD_UNDEFINED)) {
		/* The Mobile Node is not connected to a network */
		esp->state = MIP6_STATE_UNDEF;
		esp->coa = in6addr_any;
		if (esp->ha_fn != NULL) {
			_FREE(esp->ha_fn, M_TEMP);
			esp->ha_fn = NULL;
		}
		if (mip6_tunnel(NULL, NULL, MIP6_TUNNEL_DEL, MIP6_NODE_MN,
				(void *)esp))
			return;
	} else if ((prim_prefix == NULL) && (state == MIP6_MD_HOME)) {
		/* The Mobile Node is returning to the home link. Change the
		   parameters for the event-state machine. */
		esp->state = MIP6_STATE_DEREG;
		old_coa = esp->coa;
		esp->coa = esp->home_addr;

		/* Send a BU de-registration to the Home Agent. */
		bulp = mip6_bul_find(NULL, home_addr);
		if (bulp == NULL) {
			/* The event-state machine was in state undefined. */
			esp->state = MIP6_STATE_HOME;

			/* When returning home and no home registration exist
			   we can not assume the home address to be unique.
			   Perform DAD, but find the i/f address first. */
			bzero(&sin6, sizeof(struct sockaddr_in6));
			sin6.sin6_len = sizeof(struct sockaddr_in6);
			sin6.sin6_family = AF_INET6;
			sin6.sin6_addr = esp->home_addr;

			if_addr = ifa_ifwithaddr((struct sockaddr *)&sin6);
			if (if_addr == NULL)
				return;

			((struct in6_ifaddr *)if_addr)->ia6_flags |=
				IN6_IFF_TENTATIVE;
			nd6_dad_start(if_addr, NULL);
			return;
		}

		bulp->lifetime = mip6_config.hr_lifetime;
		bulp->refreshtime = bulp->lifetime;
		bulp->coa = bulp->bind_addr;

		bu_data.prefix_len = esp->prefix_len;
		bu_data.ack = 1;

		if (mip6_send_bu(bulp, &bu_data, NULL) != 0)
			return;

		/* Send a BU to the previous foreign network. */
		if ( !IN6_IS_ADDR_UNSPECIFIED(&old_coa) &&
		     (esp->ha_fn != NULL)) {
			/* Find lifetime used for the BU to the def router. */
			lifetime = mip6_prefix_lifetime(&old_coa);
			lifetime = min(lifetime, MIP6_BU_LIFETIME_DEFRTR);

			/* Create a tunnel used by the MN to receive
			   incoming tunneled packets. */
			if (mip6_tunnel(home_addr, &esp->ha_fn->addr,
					MIP6_TUNNEL_ADD,
					MIP6_NODE_MN, (void *)esp))
				return;

			mip6_send_bu2fn(&old_coa, esp->ha_fn, home_addr,
					esp->ifp, lifetime);
			_FREE(esp->ha_fn, M_TEMP);
			esp->ha_fn = NULL;
		}

		/* The Mobile Node must send a Neighbor Advertisement to inform
		   other nodes that it has arrived back to its home network.
		   The first NA will be sent in the create function, the
		   remaining NAs are sent by the timer function. */
		ll_all_addr = in6addr_linklocal_allnodes;
		na_flags = ND_NA_FLAG_OVERRIDE;
		mip6_na_create(home_addr, &ll_all_addr, home_addr,
			       esp->prefix_len, na_flags, 1);
	} else if ((prim_prefix != NULL) && (state == MIP6_MD_FOREIGN)) {
		/* If no Home Agent Address exist. Build an anycast address */
		if (IN6_IS_ADDR_UNSPECIFIED(&esp->ha_hn)) {
			mip6_build_ha_anycast(&esp->ha_hn, &esp->home_addr,
					      esp->prefix_len);
			if (IN6_IS_ADDR_UNSPECIFIED(&esp->ha_hn)) {
				log(LOG_ERR,
				    "%s: Could not create anycast address "
				    "for Mobile Node, wrong prefix length\n",
				    __FUNCTION__);
				return;
			}
		}

		if ((esp->state == MIP6_STATE_UNDEF) ||
		    (esp->state == MIP6_STATE_HOME) ||
		    (esp->state == MIP6_STATE_DEREG)) {
			/* Home Network --> Foreign Network */
			/* Update state information for the home address. */
			esp->state = MIP6_STATE_NOTREG;
			esp->coa = *prim_addr;
			if (esp->ha_fn != NULL) {
				_FREE(esp->ha_fn, M_TEMP);
				esp->ha_fn = NULL;
			}

			/* Find an existing or create a new BUL entry. */
			bulp = mip6_bul_find(NULL, &esp->home_addr);
			if (bulp == NULL) {
				bulp = mip6_bul_create(&esp->ha_hn,
						       &esp->home_addr,
						       prim_addr,
						       mip6_config.hr_lifetime,
						       1);
				if (bulp == NULL)
					return;
			} else {
				bulp->coa = *prim_addr;
				bulp->lifetime = mip6_config.hr_lifetime;
				bulp->refreshtime = bulp->lifetime;
			}

			/* Send a BU registration to the Home Agent. */
			bulp->coa = *prim_addr;
			bulp->lifetime = mip6_config.hr_lifetime;
			bulp->refreshtime = mip6_config.hr_lifetime;

			bu_data.prefix_len = esp->prefix_len;
			bu_data.ack = 1;

			if (mip6_send_bu(bulp, &bu_data, NULL) != 0)
				return;
		} else if (esp->state == MIP6_STATE_REG ||
			   esp->state == MIP6_STATE_REREG ||
			   esp->state == MIP6_STATE_REGNEWCOA ||
			   esp->state == MIP6_STATE_NOTREG) {
			/* Foreign Network --> New Foreign Network */
			/* Update state information for the home address. */
			esp->state = MIP6_STATE_REGNEWCOA;
			old_coa = esp->coa;
			esp->coa = *prim_addr;

			/* Find an existing or create a new BUL entry. */
			bulp = mip6_bul_find(NULL, &esp->home_addr);
			if (bulp == NULL) {
				bulp = mip6_bul_create(&esp->ha_hn,
						       &esp->home_addr,
						       prim_addr,
						       mip6_config.hr_lifetime,
						       1);
				if (bulp == NULL)
					return;
			}

			/* Send a BU registration to the Home Agent. */
			bulp->coa = *prim_addr;
			bulp->lifetime = mip6_config.hr_lifetime;
			bulp->refreshtime = mip6_config.hr_lifetime;
			bulp->no_of_sent_bu = 0;

			bu_data.prefix_len = esp->prefix_len;
			bu_data.ack = 1;

			if (mip6_send_bu(bulp, &bu_data, NULL) != 0)
				return;

			/* Send a BU registration to the previous default
			   router. */
			if ( !IN6_IS_ADDR_UNSPECIFIED(&old_coa) &&
			     (esp->ha_fn)) {
				/* Find lifetime to be used for the BU to
				   the def router. */
				lifetime = mip6_prefix_lifetime(&old_coa);
				lifetime = min(lifetime,
					       MIP6_BU_LIFETIME_DEFRTR);

				/* Create a tunnel used by the MN to receive
				   incoming tunneled packets. */
				if (mip6_tunnel(prim_addr, &esp->ha_fn->addr,
						MIP6_TUNNEL_MOVE,
						MIP6_NODE_MN, (void *)esp))
					return;

				mip6_send_bu2fn(&old_coa, esp->ha_fn,
						prim_addr,
						esp->ifp, lifetime);
				_FREE(esp->ha_fn, M_TEMP);
				esp->ha_fn = NULL;
			}
		}
	} else
		esp->state = MIP6_STATE_UNDEF;
}



/*
 ##############################################################################
 #
 # CONTROL SIGNAL FUNCTIONS
 # Functions for processing of incoming control signals (Binding Acknowledge-
 # ment and Binding Request option) and sub-options (Home Agents list).
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_rec_ba
 * Description: Receive a BA option and evaluate the contents.
 * Ret value:   0             Everything is OK.
 *              IPPROTO_DONE  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_rec_ba(m_in, off)
struct mbuf *m_in;  /* Mbuf containing the entire IPv6 packet */
int          off;   /* Offset from start of mbuf to start of dest option */
{
	struct mip6_esm  *esp;       /* Home address entry */
	struct mip6_bul  *bulp;      /* Entry in the Binding Update list */
	struct in6_addr  *from_src;  /* Source address in received packet */
	struct in6_addr   bind_addr; /* Binding addr in BU causing this BA */
	u_int8_t          hr_flag;
	int               error;
#if MIP6_DEBUG
	u_int8_t          var;
	int               ii, offset;
#endif

	/* Make sure that the BA contains a valid AH or ESP header. */
#if IPSEC
#ifndef __OpenBSD__
	if ( !((m_in->m_flags & M_AUTHIPHDR && m_in->m_flags & M_AUTHIPDGM) ||
	       (m_in->m_flags & M_AUTHIPDGM && m_in->m_flags & M_DECRYPTED))) {
		ip6stat.ip6s_badoptions++;
		log(LOG_ERR, "%s: No AH or ESP included in BA\n",
		    __FUNCTION__);
		return IPPROTO_DONE;
	}
#endif
#endif

	/* Make sure that the length field in the BA is >= 11. */
	if (mip6_inp->ba_opt->len < IP6OPT_BALEN) {
		ip6stat.ip6s_badoptions++;
		log(LOG_ERR, "%s: Length field in BA < 11\n", __FUNCTION__);
		return IPPROTO_DONE;
	}

	/* Make sure that the sent BU sequence number == received BA sequence
	   number. But first, find the source address for the incoming packet
	   (it may include a home address option). */
	if (mip6_inp->optflag & MIP6_DSTOPT_HA)
		from_src = &mip6_inp->ha_opt->home_addr;
	else
		from_src = &mip6_inp->ip6_src;

	bulp = mip6_bul_find(from_src, &mip6_inp->ip6_dst);
	if (bulp == NULL) {
		log(LOG_ERR, "%s: No Binding Update List entry found\n",
		    __FUNCTION__);
		return IPPROTO_DONE;
	}

	if (mip6_inp->ba_opt->seqno != bulp->seqno) {
		ip6stat.ip6s_badoptions++;
		log(LOG_ERR,
		    "%s: Received sequence number not equal to sent\n",
		    __FUNCTION__);
		return IPPROTO_DONE;
	}

#if MIP6_DEBUG
	mip6_debug("\nReceived Binding Acknowledgement\n");
	mip6_debug("IP Header Src:      %s\n", ip6_sprintf(from_src));
	mip6_debug("IP Header Dst:      %s\n",
		   ip6_sprintf(&mip6_inp->ip6_dst));
	mip6_debug("Type/Length/Status: %x / %u / %u\n",
		   mip6_inp->ba_opt->type,
		   mip6_inp->ba_opt->len, mip6_inp->ba_opt->status);
	mip6_debug("Seq no/Life time:   %u / %u\n", mip6_inp->ba_opt->seqno,
		   mip6_inp->ba_opt->lifetime);
	mip6_debug("Refresh time:       %u\n", mip6_inp->ba_opt->refresh);

	if (mip6_inp->ba_opt->len > IP6OPT_BALEN) {
		offset = mip6_opt_offset(m_in, off, IP6OPT_BINDING_ACK);
		if (offset == 0)
			goto end_debug;

		mip6_debug("Sub-options present (TLV coded)\n");
		for (ii = IP6OPT_BALEN; ii < mip6_inp->ba_opt->len; ii++) {
			if ((ii - IP6OPT_BALEN) % 16 == 0)
				mip6_debug("\t0x:");
			if ((ii - IP6OPT_BALEN) % 4 == 0)
				mip6_debug(" ");
			m_copydata(m_in, offset + 2 + ii, sizeof(var),
				   (caddr_t)&var);
			mip6_debug("%02x", var);
			if ((ii - IP6OPT_BALEN + 1) % 16 == 0)
				mip6_debug("\n");
		}
		if ((ii - IP6OPT_BALEN) % 16)
			mip6_debug("\n");
	}
  end_debug:
#endif

	/* Check the status field in the BA. */
	if (mip6_inp->ba_opt->status >= 128) {
		/* Remove the BUL entry and process the error
		   (order is important). */
		bind_addr = bulp->bind_addr;
		hr_flag = bulp->hr_flag;
		mip6_bul_delete(bulp);

		error = mip6_ba_error(from_src, &mip6_inp->ip6_dst,
				      &bind_addr, hr_flag);
		return error;
	}
	
	/* BA was accepted. Update corresponding entry in the BUL.
	   Stop retransmitting the BU. */
	bulp->no_of_sent_bu = 0;
	bulp->update_rate = MIP6_MAX_UPDATE_RATE;
	mip6_clear_retrans(bulp);

	/* If the BA was received from the Home Agent the state
	   of the event state machine shall be updated. */
	if (bulp->hr_flag) {
		esp = mip6_esm_find(&bulp->bind_addr);
		if (esp == NULL) {
			log(LOG_ERR, "%s: No event-state machine found\n",
			    __FUNCTION__);
			return IPPROTO_DONE;
		}

		/* If Dynamic Home Agent Address Discovery, change
		   HA address and remove esp->dad entry. */
		if (esp->dad) {
			esp->ha_hn = *from_src;
			bulp->dst_addr = *from_src;
			if (esp->dad->hal)
				_FREE(esp->dad->hal, M_TEMP);
			_FREE(esp->dad, M_TEMP);
			esp->dad = NULL;
		}

		/* Update the state for the home address. */
		if (esp->state == MIP6_STATE_DEREG) {
			mip6_bul_delete(bulp);

			/* Remove the tunnel for the MN */
			mip6_tunnel(NULL, NULL, MIP6_TUNNEL_DEL,
				    MIP6_NODE_MN, (void *)esp);

			/* Send BU to each CN in the BUL to remove its
			   BC entry. */
			mip6_update_cns(&esp->home_addr,
					&esp->home_addr, 0, 0);
			mip6_outq_flush();

			/* Don't set the state until BUs have been sent to
			   all CNs, otherwise the Home Address option will
			   not be added for the outgoing packet. */
			esp->state = MIP6_STATE_HOME;
			esp->coa = in6addr_any;
		} else {
			esp->state = MIP6_STATE_REG;

			/* Create or modify a tunnel used by the MN to
			   receive incoming tunneled packets. */
			if (mip6_tunnel(&esp->coa, &esp->ha_hn,
					MIP6_TUNNEL_MOVE, MIP6_NODE_MN,
					(void *)esp))
				return IPPROTO_DONE;

			/* Send BU to each CN in the BUL to update BC entry. */
			bulp->lifetime = mip6_inp->ba_opt->lifetime;
			bulp->refreshtime = mip6_inp->ba_opt->refresh;
			mip6_update_cns(&esp->home_addr, &esp->coa, 0,
					bulp->lifetime);
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_rec_br
 * Description: Receive a Binding Request option and evaluate the contents.
 * Ret value:   0             Everything is OK.
 *              IPPROTO_DONE  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_rec_br(m_in, off)
struct mbuf *m_in;  /* Mbuf containing the entire IPv6 packet */
int          off;   /* Offset from start of mbuf to start of dest option */
{
	struct mip6_opt_bu     *bu_opt;        /* BU allocated in function */
	struct in6_addr        *from_src;      /* Src address in rec packet */
	struct mip6_esm        *esp;           /* Home address entry */
	struct mip6_bul        *bulp_cn;       /* CN entry in the BU list */
	struct mip6_bul        *bulp_ha;       /* HA entry in the BU list */
	struct mip6_subbuf     *subbuf = NULL; /* Sub-options for an option */
	struct mip6_subopt_coa  altcoa;        /* Alternate care-of address */
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	long time_second = time.tv_sec;
#endif
#if MIP6_DEBUG
	const struct mbuf *m = (const struct mbuf *)m_in;
	u_int8_t  var;
	int       ii, offset;
#endif

	/* Make sure that the BA contains a valid AH or ESP header. */
	if (mip6_inp->br_opt->type != IP6OPT_BINDING_REQ) {
		ip6stat.ip6s_badoptions++;
		return IPPROTO_DONE;
	}

#if MIP6_DEBUG
	mip6_debug("\nReceived Binding Request\n");
	mip6_debug("Type/Length: %x / %u\n", mip6_inp->br_opt->type,
		   mip6_inp->br_opt->len);

	if (mip6_inp->br_opt->len > IP6OPT_BRLEN) {
		offset = mip6_opt_offset(m_in, off, IP6OPT_BINDING_REQ);
		if (offset == 0)
			goto end_debug;

		mip6_debug("Sub-options present (TLV coded)\n");
		for (ii = IP6OPT_BRLEN; ii < mip6_inp->br_opt->len; ii++) {
			if (m->m_len < offset + 2 + ii + 1)
				break;
			if ((ii - IP6OPT_BRLEN) % 16 == 0)
				mip6_debug("\t0x:");
			if ((ii - IP6OPT_BRLEN) % 4 == 0)
				mip6_debug(" ");
			m_copydata(m_in, offset + 2 + ii, sizeof(var),
				   (caddr_t)&var);
			mip6_debug("%02x", var);
			if ((ii - IP6OPT_BRLEN + 1) % 16 == 0)
				mip6_debug("\n");
		}
		if ((ii - IP6OPT_BRLEN) % 16)
			mip6_debug("\n");
	}
  end_debug:
#endif

	/* Check if the BR includes a Unique Identifier sub-option. */
	if (mip6_inp->br_opt->len > IP6OPT_BRLEN) {
		/* Received tunneled Router Advertisement when the MN's home
		   subnet is renumbered while the MN is away from home. */
		/* XXX Code have to be added. */
	} else {
		/* A CN is requesting the MN to send a BU to update its BC. */
		/* Find the source address for the incoming packet (it may
		   include a home address option). */
		if (mip6_inp->optflag & MIP6_DSTOPT_HA)
			from_src = &mip6_inp->ha_opt->home_addr;
		else
			from_src = &mip6_inp->ip6_src;

		/* Find out which lifetime to use in the BU */
		bulp_cn = mip6_bul_find(from_src, &mip6_inp->ip6_dst);
		if (bulp_cn == NULL)
			return IPPROTO_DONE;

		esp = mip6_esm_find(&mip6_inp->ip6_dst);
		if (esp == NULL) {
			log(LOG_ERR, "%s: no event-state machine found\n",
			    __FUNCTION__);
			return IPPROTO_DONE;
		}

		bulp_ha = mip6_bul_find(&esp->ha_hn, &mip6_inp->ip6_dst);
		if (bulp_ha == NULL)
			return IPPROTO_DONE;

		if (bulp_ha->lifetime > bulp_cn->lifetime) {
			/* Send a BU to the previous default router. */
			bulp_cn->seqno += 1;
			bu_opt = mip6_create_bu(0, 0, 0, bulp_cn->seqno,
						bulp_ha->lifetime);
			if (bu_opt == NULL)
				return IPPROTO_DONE;

			altcoa.type = IP6SUBOPT_ALTCOA;
			altcoa.len = IP6OPT_COALEN;
			altcoa.coa = bulp_cn->coa;
			if (mip6_store_subopt(&subbuf, (caddr_t)&altcoa)
			    != 0) {
				if (subbuf)
					_FREE(subbuf, M_TEMP);
				return IPPROTO_DONE;
			}

			mip6_outq_create(bu_opt, subbuf, &esp->home_addr,
					 from_src, NOT_SENT);

			bulp_cn->lifetime = bulp_ha->lifetime;
			bulp_cn->refreshtime = bulp_ha->lifetime;
			bulp_cn->lasttime = time_second;
			bulp_cn->no_of_sent_bu = 0;
			bulp_cn->update_rate = MIP6_MAX_UPDATE_RATE;
			mip6_clear_retrans(bulp_cn);
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_rec_hal
 * Description: Performs Dynamic Home Agent Address Discovery. Called when a
 *              list of global home agent addresses is received. Checks if the
 *              received packets source address is in the list. If not it shall
 *              be added as the first entry in the list.
 *              Save the home agent address list in the event-state machine
 *              and send a BU to the first address in the list.
 * Note:        The timeout used in the BU is a trade off between how long
 *              time it shall wait before the next entry in the list is picked
 *              and, if successful first registration, the time to perform
 *              next registration. I believe 16 - 32 seconds will be fine.
 * Ret value:   0             Everything is OK.
 *              IPPROTO_DONE  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_rec_hal(src, dst, hal)
struct in6_addr         *src;  /* Incoming packet source address */
struct in6_addr         *dst;  /* Incoming packet destination address */
struct mip6_subopt_hal  *hal;  /* List of HA's on the home link */
{
	struct mip6_esm        *esp;     /* Event-state machine */
	struct mip6_bul        *bulp;    /* Entry in the Binding Update list */
	struct mip6_subbuf     *subbuf;  /* Buffer containing sub-options */
	struct mip6_bu_data     bu_data; /* Data used when a BU is created */
	int    found, ii, new_len, index;

	subbuf = NULL;

	/* Find the event-state machine */
	esp = mip6_esm_find(dst);
	if (esp == NULL) {
		log(LOG_ERR,
		    "%s: Couldn't find an event-state machine for "
		    "home address %s\n",
		    __FUNCTION__, ip6_sprintf(dst));
		return IPPROTO_DONE;
	}

	/* If the incoming source address is not in the list of home
	   agents it is treated as the HA with highest preference.
	   Otherwise, the HA's are tried in the listed order. */
	found = 0;
	if (hal == NULL)
		new_len = IP6OPT_HALEN;
	else {
		index = hal->len / IP6OPT_HALEN;
		for (ii = 0; ii < index; ii++) {
			if (IN6_ARE_ADDR_EQUAL(&hal->halist[ii], src)) {
				found = 1;
				break;
			}
		}
		if (found)
			new_len = hal->len;
		else
			new_len = hal->len + IP6OPT_HALEN;
	}

	/* Store the home agents list in the event-state machine. Add the
	   incoming packets source address if necessary. */
	esp->dad = (struct mip6_dad *)MALLOC(sizeof(struct mip6_dad),
					     M_TEMP, M_WAITOK);
	if (esp->dad == NULL)
		return IPPROTO_DONE;
	bzero(esp->dad, sizeof(struct mip6_dad));

	index = new_len / IP6OPT_HALEN;
	esp->dad->hal = (struct mip6_subopt_hal *)
		MALLOC(sizeof(struct mip6_subopt_hal) +
		       ((index - 1) * sizeof(struct in6_addr)),
		       M_TEMP, M_WAITOK);
	if (esp->dad->hal == NULL)
		return IPPROTO_DONE;

	esp->dad->hal->type = IP6SUBOPT_HALIST;
	esp->dad->hal->len = new_len;
	if (found) {
		for (ii = 0; ii < index; ii++) {
			bcopy(&hal->halist[ii], &esp->dad->hal->halist[ii],
			      sizeof(struct in6_addr));
		}
	} else {
		bcopy(src, &esp->dad->hal->halist[0], sizeof(struct in6_addr));
		for (ii = 0; ii < index - 1; ii++) {
			bcopy(&hal->halist[ii], &esp->dad->hal->halist[ii+1],
			      sizeof(struct in6_addr));
		}
	}

	/* Create a BUL entry. If there exist one already something is
	   wrong and an error message is sent to the console. */
	bulp = mip6_bul_find(src, dst);
	if (bulp != NULL) {
		log(LOG_ERR,
		    "%s: A BUL entry found but it shouldn't have been. "
		    "Internal error that must be looked into\n", __FUNCTION__);
		return IPPROTO_DONE;
	}

	bulp = mip6_bul_create(&esp->dad->hal->halist[0], &esp->home_addr,
			       &esp->coa, MIP6_BU_LIFETIME_DHAAD, 1);
	if (bulp == NULL)
		return IPPROTO_DONE;

	/* Send a BU registration to the Home Agent with highest preference. */
	bu_data.prefix_len = esp->prefix_len;
	bu_data.ack = 1;

	if (mip6_send_bu(bulp, &bu_data, subbuf) != 0)
		return IPPROTO_DONE;

	/* Set index to next entry to be used in the list.
	   Starts at 0 (which has been sent in this function) */
	if ((esp->dad->hal->len / IP6OPT_HALEN) == 1)
		esp->dad->index = 0;
	else
		esp->dad->index = 1;

	return 0;
};



/*
 ******************************************************************************
 * Function:    mip6_rec_ramn
 * Description: Processed by a Mobile Node. Includes a Router Advertisement
 *              with a H-bit set in the flags variable (checked by the calling
 *              function).
 *              The global unicast address for the home agent with the highest
 *              preference and the time when it expires are stored.
 * Ret value:   0 Everything is OK. Otherwise appropriate error code.
 ******************************************************************************
 */
int
mip6_rec_ramn(m, off)
struct mbuf  *m;    /* Mbuf containing the entire IPv6 packet */
int           off;  /* Offset from start of mbuf to start of RA */
{
	struct ip6_hdr            *ip6;  /* IPv6 header */
	struct nd_router_advert   *ra;   /* Router Advertisement */
	struct mip6_esm           *esp;  /* Event-state machine */
	struct nd_opt_hai         *hai;  /* Home Agent information option */
	struct nd_opt_prefix_info *pi;   /* Ptr to prefix information */
	u_int8_t        *opt_ptr;        /* Ptr to current option in RA */
	int              cur_off;        /* Cur offset from start of RA */
	caddr_t          icmp6msg;       /* Copy of mbuf (consequtively) */
	int16_t          tmp_pref;
	time_t           tmp_lifetime;
	int              icmp6len;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	long time_second = time.tv_sec;
#endif

	/* Find out if the RA can be processed */
	ip6 = mtod(m, struct ip6_hdr *);
	if (ip6->ip6_hlim != 255) {
		log(LOG_INFO,
		    "%s: Invalid hlim %d in Router Advertisement\n",
		    __FUNCTION__,
		    ip6->ip6_hlim);
		return 0;
	}

	if (!IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)) {
		log(LOG_INFO,
		    "%s: Source address %s is not link-local\n", __FUNCTION__,
		    ip6_sprintf(&ip6->ip6_src));
		return 0;
	}

	/* The mbuf data must be stored consequtively to be able to
	   cast data from it. */
	icmp6len = m->m_pkthdr.len - off;
	icmp6msg = (caddr_t)MALLOC(icmp6len, M_TEMP, M_WAITOK);
	if (icmp6msg == NULL)
		return IPPROTO_DONE;

	m_copydata(m, off, icmp6len, icmp6msg);
	ra = (struct nd_router_advert *)icmp6msg;

	/* First, if a Home Agent Information option is present then the Home
	   Agent preference and lifetime is taken from the option. */
	cur_off = sizeof(struct nd_router_advert);
	tmp_lifetime = ntohl(ra->nd_ra_router_lifetime);
	tmp_pref = 0;

	while (cur_off < icmp6len) {
		opt_ptr = ((caddr_t)icmp6msg + cur_off);
		if (*opt_ptr == ND_OPT_HA_INFORMATION) {
			/* Check the home agent information option */
			hai = (struct nd_opt_hai *)opt_ptr;
			if (hai->nd_opt_hai_len != 1) {
				ip6stat.ip6s_badoptions++;
				return IPPROTO_DONE;
			}

			tmp_pref = ntohs(hai->nd_opt_hai_pref);
			tmp_lifetime = ntohs(hai->nd_opt_hai_lifetime);
			cur_off += 8;
			continue;
		} else {
			if (*(opt_ptr + 1) == 0) {
				ip6stat.ip6s_badoptions++;
				return IPPROTO_DONE;
			}
			cur_off += *(opt_ptr + 1) * 8;
		}
	}

	/* Go through all prefixes and store global address for the Home
	   Agent with the highest preference. */
	cur_off = sizeof(struct nd_router_advert);
	while (cur_off < icmp6len) {
		opt_ptr = ((caddr_t)icmp6msg + cur_off);
		if (*opt_ptr == ND_OPT_PREFIX_INFORMATION) {
			/* Check the prefix information option */
			pi = (struct nd_opt_prefix_info *)opt_ptr;
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
			if (((pi->nd_opt_pi_prefix.s6_addr8[0] & 0xe0) >
			     0x10) && (pi->nd_opt_pi_prefix_len != 64)) {
				cur_off += 4 * 8;
				continue;
			}

			/* Only save the address if it's equal to the coa. */
			for (esp = mip6_esmq; esp; esp = esp->next) {
				if (in6_are_prefix_equal(
					&pi->nd_opt_pi_prefix,
					&esp->coa,
					pi->nd_opt_pi_prefix_len)) {
					if (esp->ha_fn == NULL) {
						esp->ha_fn = (struct mip6_hafn *)
							MALLOC(sizeof(struct mip6_hafn), M_TEMP, M_WAITOK);
						if (esp->ha_fn == NULL)
							return ENOBUFS;
						bzero(esp->ha_fn, sizeof(struct mip6_hafn));

						esp->ha_fn->addr = pi->nd_opt_pi_prefix;
						esp->ha_fn->prefix_len = pi->nd_opt_pi_prefix_len;
						esp->ha_fn->pref = tmp_pref;
						esp->ha_fn->time = time_second + tmp_lifetime;
					} else {
						if (tmp_pref > esp->ha_fn->pref) {
							esp->ha_fn->addr = pi->nd_opt_pi_prefix;
							esp->ha_fn->prefix_len = pi->nd_opt_pi_prefix_len;
							esp->ha_fn->pref = tmp_pref;
							esp->ha_fn->time = time_second + tmp_lifetime;
						} else
							esp->ha_fn->time = time_second + tmp_lifetime;
					}
				}
			}
			
			cur_off += 4 * 8;
			continue;
		} else {
			if (*(opt_ptr + 1) == 0) {
				ip6stat.ip6s_badoptions++;
				return IPPROTO_DONE;
			}
			cur_off += *(opt_ptr + 1) * 8;
		}
	}
	return 0;
}


/*
 ******************************************************************************
 * Function:    mip6_route_optimize
 * Description: When a tunneled packet is received a BU shall be sent to the
 *              CN if no Binding Update List entry exist or if the rate limit
 *              for sending BUs for an existing BUL entry is not exceded.
 * Ret value:   0             Everything is OK.
 *              IPPROTO_DONE  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_route_optimize(m)
struct mbuf *m;  /* Mbuf containing the entire IPv6 packet */
{
	struct ip6_hdr         *ip6;
	struct mip6_esm        *esp;
	struct mip6_bul        *bulp, *bulp_hr;
	struct mip6_subbuf     *subbuf;   /* Buffer containing sub-options */
	struct mip6_bu_data     bu_data;  /* Data used when a BU is created */
	struct mip6_subopt_coa  altcoa;   /* Alternate care-of address */
	time_t                  t;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	long time_second = time.tv_sec;
#endif

	/* Make sure that all requirements are meet for sending a BU to
	   the original sender of the packet. */
	if (!(m->m_flags & M_MIP6TUNNEL))
		return 0;

	ip6 = mtod(m, struct ip6_hdr *);
	esp = mip6_esm_find(&ip6->ip6_dst);
	if (esp == NULL)
		return 0;

	/* Try to find an existing BUL entry. */
	bulp = mip6_bul_find(&ip6->ip6_src, &esp->home_addr);
	if (bulp == NULL) {
		/* Some information needed from the BU home registration */
		bulp_hr = mip6_bul_find(NULL, &esp->home_addr);
		if (bulp_hr == NULL)
			return 0;
		bulp = mip6_bul_create(&ip6->ip6_src, &esp->home_addr,
				       &esp->coa, bulp_hr->lifetime, 0);
		if (bulp == NULL)
			return IPPROTO_DONE;
	} else {
		/* If the existing BUL entry is waiting for an ack or
		   has disabled sending BU, no BU shall be sent. */
		if ((bulp->state) || (bulp->bu_flag == 0))
			return 0;

		/* Check the rate limiting for sending Binding Updates */
		t = (time_t)time_second;
#if MIP6_DEBUG
		mip6_debug("%s: Rate limiting for sending BU\n", __FUNCTION__);
		mip6_debug("(time - bulp->lasttime) < bulp->update_rate\n");
		mip6_debug("time               = %lu\n", (u_long)t);
		mip6_debug("bulp->lasttimetime = %lu\n", bulp->lasttime);
		mip6_debug("bulp->update_rate  = %d\n", bulp->update_rate);
#endif
		if ((t - bulp->lasttime) < bulp->update_rate)
			return 0;
	}

	/* OK we have to send a BU. */
	subbuf = NULL;
	bu_data.prefix_len = esp->prefix_len;
	bu_data.ack = 0;

	altcoa.type = IP6SUBOPT_ALTCOA;
	altcoa.len = IP6OPT_COALEN;
	altcoa.coa = bulp->coa;
	if (mip6_store_subopt(&subbuf, (caddr_t)&altcoa)) {
		if (subbuf) _FREE(subbuf, M_TEMP);
		return IPPROTO_DONE;
	}

	if (mip6_send_bu(bulp, &bu_data, subbuf) != 0)
		return IPPROTO_DONE;
	return 0;
}



/*
 ##############################################################################
 #
 # SENDING FUNCTIONS
 # These functions are called when an IPv6 packet has been created internally
 # by MIPv6 and shall be sent directly to its destination or when an option
 # (BU, BA, BR) has been created and shall be stored in the mipv6 output queue
 # for piggybacking on the first outgoing packet sent to the node.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_send_bu
 * Description: Send a Binding Update option to a node (CN, HA or MN). A new
 *              IPv6 packet is built including an IPv6 header and a Destination
 *              header (where the BU is stored).
 * Arguments:   bulp   - BUL entry for which the BU is sent.
 *              data   - BU data needed when the BU option is created. NULL
 *                       if the BU option stored in the BUL entry is used.
 *              subopt - Sub-options for the BU. NULL if the BU sub-options
 *                       stored in the BUL entry is used.
 * Note:        The following combinations of indata are possible:
 *              data == NULL && subbuf == NULL Use existing data, i.e used for
 *                                             retransmission
 *              data != NULL && subbuf == NULL Clear existing data and send a
 *                                             new BU without sub-options
 *              data != NULL && subbuf != NULL Clear existing data and send a
 *                                             new BU with new sub-options
 * Ret value:   0 if everything OK. Otherwise appropriate error code.
 ******************************************************************************
 */
int
mip6_send_bu(bulp, data, subbuf)
struct mip6_bul      *bulp;
struct mip6_bu_data  *data;
struct mip6_subbuf   *subbuf;
{
	struct mbuf         *m_ip6;      /* IPv6 header stored in a mbuf */
	struct ip6_pktopts  *pktopt;     /* Options for IPv6 packet */
	struct mip6_opt_bu  *bu_opt;     /* Binding Update option */
	struct mip6_subbuf  *bu_subopt;  /* Binding Update sub-options */
	struct mip6_esm     *esp;        /* Home address entry */
	int                  error;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	long time_second = time.tv_sec;
#endif
#if MIP6_DEBUG
	int                  ii;
	u_int8_t             var;
#endif

	/* Make sure that it's allowed to send a BU */
	if (bulp == NULL)
		return 0;

	if (!bulp->bu_flag) {
		log(LOG_INFO,
		    "%s: BU not sent to host %s due to an ICMP Parameter "
		    "Problem, Code 2, when a BU was sent previously\n",
		    __FUNCTION__, ip6_sprintf(&bulp->dst_addr));
		return 0;
	}

	/* Only send BU if we are not in state UNDEFINED */
	esp = mip6_esm_find(&bulp->bind_addr);
	if (esp == NULL) {
		log(LOG_ERR, "%s: We should never come here\n", __FUNCTION__);
		return 0;
	} else if (esp->state == MIP6_STATE_UNDEF) {
		log(LOG_INFO,
		    "%s: Mobile Node with home address %s not connected to "
		    "any network. Binding Update could not be sent.\n",
		    __FUNCTION__, ip6_sprintf(&bulp->bind_addr));
		return 0;
	}

	/* Evaluate parameters according to the note in the function header */
	if ((data == NULL) && (subbuf == NULL)) {
		if ((bulp->state == NULL) || (bulp->state->bu_opt == NULL)) {
			log(LOG_ERR,
			    "%s: No existing BU option to send\n",
			    __FUNCTION__);
			return 0;
		}
		bulp->seqno += 1;
		bu_opt = bulp->state->bu_opt;
		bu_opt->seqno = bulp->seqno;
		bu_subopt = bulp->state->bu_subopt;
	} else if (data != NULL) {
		mip6_clear_retrans(bulp);
		if (data->ack) {
			bulp->state = mip6_create_retrans(bulp);
			if (bulp->state == NULL)
				return ENOBUFS;
		}

		bulp->seqno += 1;
		bu_opt = mip6_create_bu(data->prefix_len, data->ack,
					bulp->hr_flag,
					bulp->seqno, bulp->lifetime);
		if (bu_opt == NULL) {
			mip6_clear_retrans(bulp);
			bulp->seqno -= 1;
			return ENOBUFS;
		}

		if (data->ack) {
			bulp->state->bu_opt = bu_opt;
			bulp->state->bu_subopt = subbuf;
			bu_subopt = bulp->state->bu_subopt;
		} else
			bu_subopt = subbuf;
	} else {
		log(LOG_ERR,
		    "%s: Function parameter error. We should not come here\n",
		    __FUNCTION__);
		return 0;
	}

	/* Allocate necessary memory and send the BU */
	pktopt = (struct ip6_pktopts *)MALLOC(sizeof(struct ip6_pktopts),
					      M_TEMP, M_NOWAIT);
	if (pktopt == NULL)
		return ENOBUFS;
	bzero(pktopt, sizeof(struct ip6_pktopts));

	pktopt->ip6po_hlim = -1;    /* -1 means to use default hop limit */
	m_ip6 = mip6_create_ip6hdr(&bulp->bind_addr, &bulp->dst_addr,
				   IPPROTO_NONE);
	if(m_ip6 == NULL) {
		_FREE(pktopt, M_TEMP);
		return ENOBUFS;
	}

	pktopt->ip6po_dest2 = mip6_create_dh((void *)bu_opt, bu_subopt,
					     IPPROTO_NONE);
	if(pktopt->ip6po_dest2 == NULL) {
		_FREE(pktopt, M_TEMP);
		_FREE(m_ip6, M_TEMP);
		return ENOBUFS;
	}

	mip6_config.enable_outq = 0;
	error = ip6_output(m_ip6, pktopt, NULL, 0, NULL, NULL);
	if (error) {
		_FREE(pktopt->ip6po_dest2, M_TEMP);
		_FREE(pktopt, M_TEMP);
		mip6_config.enable_outq = 1;
		log(LOG_ERR,
		    "%s: ip6_output function failed to send BU, error = %d\n",
		    __FUNCTION__, error);
		return error;
	}
	mip6_config.enable_outq = 1;

	/* Update Binding Update List variables. */
	bulp->lasttime = time_second;
	bulp->no_of_sent_bu += 1;

	if ( !(bu_opt->flags & MIP6_BU_AFLAG)) {
		if (bulp->no_of_sent_bu >= MIP6_MAX_FAST_UPDATES)
			bulp->update_rate = MIP6_SLOW_UPDATE_RATE;
	}

#if MIP6_DEBUG
	mip6_debug("\nSent Binding Update option (0x%x)\n", bu_opt);
	mip6_debug("IP Header Src:     %s\n", ip6_sprintf(&bulp->bind_addr));
	mip6_debug("IP Header Dst:     %s\n", ip6_sprintf(&bulp->dst_addr));
	mip6_debug("Type/Length/Flags: %x / %u / ", bu_opt->type, bu_opt->len);
	if (bu_opt->flags & MIP6_BU_AFLAG)
		mip6_debug("A ");
	if (bu_opt->flags & MIP6_BU_HFLAG)
		mip6_debug("H ");
	if (bu_opt->flags & MIP6_BU_RFLAG)
		mip6_debug("R ");
	mip6_debug("\n");
	mip6_debug("Seq no/Life time:  %u / %u\n", bu_opt->seqno,
		   bu_opt->lifetime);
	mip6_debug("Prefix length:     %u\n", bu_opt->prefix_len);

	if (bu_subopt) {
		mip6_debug("Sub-options present (TLV coded)\n");
		for (ii = 0; ii < bu_subopt->len; ii++) {
			if (ii % 16 == 0)
				mip6_debug("\t0x:");
			if (ii % 4 == 0)
				mip6_debug(" ");
			bcopy((caddr_t)&bu_subopt->buffer[ii],
			      (caddr_t)&var, 1);
			mip6_debug("%02x", var);
			if ((ii + 1) % 16 == 0)
				mip6_debug("\n");
		}
		if (ii % 16)
			mip6_debug("\n");
	}
#endif

	_FREE(pktopt->ip6po_dest2, M_TEMP);
	_FREE(pktopt, M_TEMP);
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_send_bu2fn
 * Description: Create a new or modify an existing Binding Update List entry,
 *              create a Bindig Update option and a new temporary event-state
 *              machine and send the Binding Update option to a Home Agent at
 *              the previous foreign network.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_send_bu2fn(old_coa, old_ha, coa, esm_ifp, lifetime)
struct in6_addr  *old_coa;   /* Previous care-of address */
struct mip6_hafn *old_ha;    /* Previous Home Agent address */
struct in6_addr  *coa;       /* Current coa or home address */
struct ifnet     *esm_ifp;   /* Physical i/f used by event-state machine */
u_int32_t         lifetime;  /* Lifetime for BU */
{
	struct mip6_esm        *esp;      /* ESM for prev COA */
	struct mip6_bul        *bulp;     /* BU list entry*/
	struct mip6_subbuf     *subbuf;   /* Buffer containing sub-options */
	struct mip6_bu_data     bu_data;  /* Data used when a BU is created */
	struct mip6_subopt_coa  altcoa;   /* Alternate care-of address */
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	long time_second = time.tv_sec;
#endif

	/* Make sure that the Home Agent at the previous network exist and
	   that it's still valid. */
	if (old_ha == NULL)
		return;
	else {
		if (time_second > old_ha->time) {
			log(LOG_INFO,
			    "%s: Timer had expired for Home Agent on "
			    "previous network. No BU sent\n",
			    __FUNCTION__);
			return;
		}
	}

	/* Find an existing or create a new BUL entry. */
	bulp = mip6_bul_find(NULL, old_coa);
	if (bulp == NULL) {
		bulp = mip6_bul_create(&old_ha->addr, old_coa, coa,
				       lifetime, 1);
		if (bulp == NULL)
			return;
	} else {
		bulp->dst_addr = old_ha->addr;
		bulp->coa = *coa;
		bulp->lifetime = lifetime;
		bulp->refreshtime = lifetime;
		mip6_clear_retrans(bulp);
	}

	/* Create an event-state machine to be used when the home address
	   option is created for outgoing packets. The event-state machine
	   must be removed when the BUL entry is removed. */
	esp = mip6_esm_create(esm_ifp, &old_ha->addr, coa, old_coa, 0,
			      MIP6_STATE_NOTREG, TEMPORARY,
			      MIP6_BU_LIFETIME_DEFRTR);
	if (esp == NULL)
		return;

	/* Send the Binding Update option */
	subbuf = NULL;

	bu_data.prefix_len = 0;
	bu_data.ack = 0;

	altcoa.type = IP6SUBOPT_ALTCOA;
	altcoa.len = IP6OPT_COALEN;
	altcoa.coa = *coa;
	if (mip6_store_subopt(&subbuf, (caddr_t)&altcoa)) {
		if (subbuf)
			_FREE(subbuf, M_TEMP);
		return;
	}

	if (mip6_send_bu(bulp, &bu_data, subbuf) != 0)
		return;
}



/*
 ******************************************************************************
 * Function:    mip6_update_cns
 * Description: Search the BUL for each entry with a matching home address for
 *              which no Binding Update has been sent for the new COA.
 *              Call a function for queueing the BU.
 * Note:        Since this BU is stored in the MN for a couple of seconds
 *              before it is piggybacked or flashed from the queue it may
 *              not have the ack-bit set.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_update_cns(home_addr, coa, prefix_len, lifetime)
struct in6_addr  *home_addr;   /* Home Address for MN */
struct in6_addr  *coa;         /* New Primary COA for MN */
u_int8_t          prefix_len;  /* Prefix length for Home Address */
u_int32_t         lifetime;    /* Lifetime for BU registration */
{
	struct mip6_bul  *bulp;    /* Entry in the Binding Update List */
	
	/* Try to find existing entry in the BUL. Home address must match. */
	for (bulp = mip6_bulq; bulp;) {
		if (IN6_ARE_ADDR_EQUAL(home_addr, &bulp->bind_addr) &&
		    !IN6_ARE_ADDR_EQUAL(coa, &bulp->coa)) {
			/* Queue a BU for transmission to the node. */
			mip6_queue_bu(bulp, home_addr, coa,
				      prefix_len, lifetime);

			/* Remove BUL entry if it's a de-registration. */
			if (IN6_ARE_ADDR_EQUAL(home_addr, coa) ||
			    (lifetime == 0))
				bulp = mip6_bul_delete(bulp);
			else
				bulp = bulp->next;
		} else
			bulp = bulp->next;
	}
}



/*
 ******************************************************************************
 * Function:    mip6_queue_bu
 * Description: Create a BU and a sub-option (alternate care-of address).
 *              Update the BUL entry and store it in the output queue for
 *              piggy-backing.
 * Note:        Since this BU is stored in the MN for a couple of seconds
 *              before it is piggybacked or flashed from the queue it may
 *              not have the ack-bit set.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_queue_bu(bulp, home_addr, coa, prefix_len, lifetime)
struct mip6_bul  *bulp;       /* Entry in the Binding Update List */
struct in6_addr  *home_addr;  /* Home Address for MN */
struct in6_addr  *coa;        /* New Primary COA for MN */
u_int8_t          prefix_len; /* Prefix length for Home Address */
u_int32_t         lifetime;   /* Lifetime for BU registration */
{
	struct mip6_opt_bu     *bu_opt;  /* BU allocated in this function */
	struct mip6_subbuf     *subbuf;  /* Buffer containing sub-options */
	struct mip6_subopt_coa  altcoa;  /* Alternate care-of address */
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	long time_second = time.tv_sec;
#endif

	/* Check if it's allowed to send a BU to this node. */
	if ((coa == NULL) || (bulp == NULL))
		return;

	if (bulp->bu_flag == 0) {
		log(LOG_INFO,
		    "%s: BU not sent to host %s due to an ICMP Parameter "
		    "Problem, Code 2, when a BU was sent previously\n",
		    __FUNCTION__, ip6_sprintf(&bulp->dst_addr));
		return;
	}

	/* Create the sub-option */
	subbuf = NULL;
	altcoa.type = IP6SUBOPT_ALTCOA;
	altcoa.len = IP6OPT_COALEN;
	altcoa.coa = *coa;
	if (mip6_store_subopt(&subbuf, (caddr_t)&altcoa)) {
		if (subbuf)
			_FREE(subbuf, M_TEMP);
		return;
	}

	/* Create a BU. */
	bulp->seqno += 1;
	bu_opt = mip6_create_bu(prefix_len, 0, 0, bulp->seqno, lifetime);
	if (bu_opt == NULL) {
		log(LOG_ERR, "%s: Could not create a BU\n", __FUNCTION__);
		return;
	}

	/* Update BUL entry */
	bulp->coa = *coa;
	bulp->lifetime = lifetime;
	bulp->refreshtime = lifetime;
	bulp->lasttime = time_second;
	bulp->no_of_sent_bu += 1;
	mip6_clear_retrans(bulp);

	/* Add entry to the output queue for transmission to the CN. */
	mip6_outq_create(bu_opt, subbuf, home_addr, &bulp->dst_addr, NOT_SENT);
}



/*
 ##############################################################################
 #
 # UTILITY FUNCTIONS
 # Miscellaneous functions needed for processing of incoming control signals
 # or events originated from the move detection algorithm.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_create_bu
 * Description: Create a Binding Update option for transmission.
 * Ret value:   Pointer to the BU option or NULL.
 * Note:        Variable seqno and lifetime set in function
 *              mip6_update_bul_entry.
 ******************************************************************************
 */
struct mip6_opt_bu *
mip6_create_bu(prefix_len, ack, hr, seqno, lifetime)
u_int8_t   prefix_len;  /* Prefix length for Home Address */
int        ack;         /* Ack required (0 = FALSE otherwise TRUE) */
int        hr;          /* Home Registration (0 = FALSE otherwise TRUE) */
u_int16_t  seqno;       /* Sequence number */
u_int32_t  lifetime;    /* Suggested lifetime for the BU registration */
{
	struct mip6_opt_bu  *bu_opt;  /* BU allocated in this function */

	/* Allocate and store Binding Update option data */
	bu_opt = (struct mip6_opt_bu *)MALLOC(sizeof(struct mip6_opt_bu),
					      M_TEMP, M_WAITOK);
	if (bu_opt == NULL)
		return NULL;
	bzero(bu_opt, sizeof(struct mip6_opt_bu));

	bu_opt->type = IP6OPT_BINDING_UPDATE;
	bu_opt->len = IP6OPT_BULEN;
	bu_opt->seqno = seqno;
	bu_opt->lifetime = lifetime;

	/* The prefix length field is valid only for "home registration" BU. */
	if (hr) {
		bu_opt->flags |= MIP6_BU_HFLAG;
		bu_opt->prefix_len = prefix_len;
		if (ip6_forwarding)
			bu_opt->flags |= MIP6_BU_RFLAG;
	} else
		bu_opt->prefix_len = 0;

	if (ack)
		bu_opt->flags |= MIP6_BU_AFLAG;

#if MIP6_DEBUG
	mip6_debug("\nBinding Update option created (0x%x)\n", bu_opt);
#endif
	return bu_opt;
}



/*
 ******************************************************************************
 * Function:    mip6_stop_bu
 * Description: Stop sending a Binding Update to the host that has generated
 *              the icmp error message.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_stop_bu(ip6_dst)
struct in6_addr *ip6_dst;   /* Host that generated ICMP error message */
{
	struct mip6_bul *bulp;  /* Entry in the BU list */

	/* No future BU shall be sent to this destination. */
	for (bulp = mip6_bulq; bulp; bulp = bulp->next) {
		if (IN6_ARE_ADDR_EQUAL(ip6_dst, &bulp->dst_addr))
			bulp->bu_flag = 0;
	}
}



/*
 ******************************************************************************
 * Function:    mip6_ba_error
 * Description: Each incoming BA error is taken care of by this function.
 *              If a registration to the Home Agent failed then dynamic home
 *              agent address discovery shall be performed. If a de-regi-
 *              stration failed then perform the same actions as when a
 *              BA with status equals to 0 is received.
 *              If a registration or de-registration to the CN failed then
 *              the error is logged, no further action is taken.
 *              If dynamic home agent address discovery already has been
 *              done then take the next entry in the list. If its just one
 *              entry in the list discard it and send a BU with destination
 *              address equals to Home Agents anycast address.
 * Ret value:   0             Everything is OK.
 *              IPPROTO_DONE  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_ba_error(src, dst, bind_addr, hr_flag)
struct in6_addr  *src;        /* Src address for received BA option */
struct in6_addr  *dst;        /* Dst address for received BA option */
struct in6_addr  *bind_addr;  /* Binding addr in BU causing this error */
u_int8_t          hr_flag;    /* Home reg flag in BU causing this error */
{
	struct mip6_bul     *bulp;     /* New BUL entry*/
	struct mip6_esm     *esp;      /* Home address entry */
	struct in6_addr     *dst_addr;
	struct mip6_bu_data  bu_data;  /* Data used when a BU is created */
	u_int32_t            lifetime;
	int                  error, max_index;

	if (mip6_inp->ba_opt->status == MIP6_BA_STATUS_UNSPEC) {
		/* Reason unspecified
		   Received when either a Home Agent or Correspondent Node
		   was not able to process the BU. */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Reason unspecified) from host %s\n",
		    mip6_inp->ba_opt->status, ip6_sprintf(src));
	} else if (mip6_inp->ba_opt->status == MIP6_BA_STATUS_PROHIBIT) {
		/* Administratively prohibited */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Administratively prohibited) from host %s\n",
		    mip6_inp->ba_opt->status, ip6_sprintf(src));
		log(LOG_INFO, "Contact your system administrator\n");
	} else if (mip6_inp->ba_opt->status == MIP6_BA_STATUS_RESOURCE) {
		/* Insufficient resources
		   Received when a Home Agent receives a BU with the H-bit
		   set and insufficient space exist or can be reclaimed
		   (sec. 8.7). */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Insufficient resources) from host %s\n",
		    mip6_inp->ba_opt->status, ip6_sprintf(src));
	} else if (mip6_inp->ba_opt->status == MIP6_BA_STATUS_HOMEREGNOSUP) {
		/* Home registration not supported
		   Received when a primary care-of address registration
		   (sec. 9.3) is done and the node is not a router
		   implementing Home Agent functionality. */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Home registration not supported) from host %s\n",
		    mip6_inp->ba_opt->status, ip6_sprintf(src));
	} else if (mip6_inp->ba_opt->status == MIP6_BA_STATUS_SUBNET) {
		/* Not home subnet
		   Received when a primary care-of address registration
		   (sec. 9.3) is done and the home address for the binding
		   is not an on-link IPv6 address with respect to the Home
		   Agent's current prefix list. */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Not home subnet) from host %s\n",
		    mip6_inp->ba_opt->status, ip6_sprintf(src));
	} else if (mip6_inp->ba_opt->status == MIP6_BA_STATUS_DHAAD) {
		/* Dynamic Home Agent Address Discovery
		   Received when a Mobile Node is trying to find out the
		   global address of the home agents on its home subnetwork
		   (sec 9.2). */
		error = mip6_rec_hal(src, dst, mip6_inp->hal);
		return error;
	} else if (mip6_inp->ba_opt->status == MIP6_BA_STATUS_IFLEN) {
		/* Incorrect subnet prefix length
		   Received when a primary care-of address registration
		   (sec. 9.3) is done and the prefix length in the BU
		   differs from the length of the home agent's own knowledge
		   of the subnet prefix length on the home link. */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Incorrect subnet prefix length) from host %s\n",
		    mip6_inp->ba_opt->status, ip6_sprintf(src));
	} else if (mip6_inp->ba_opt->status == MIP6_BA_STATUS_NOTHA) {
		/* Not Home Agent for this Mobile Node
		   Received when a primary care-of address de-registration
		   (sec. 9.4) is done and the Home Agent has no entry for
		   this mobil node marked as "home registration" in its
		   Binding Cache. */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Not Home Agent for this Mobile Node) from host %s\n",
		    mip6_inp->ba_opt->status, ip6_sprintf(src));
	} else {
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d (Unknown) "
		    "from host %s\n",
		    mip6_inp->ba_opt->status, ip6_sprintf(src));
	}

	/* Furthr processing according to the desription in the header. */
	if (hr_flag) {
		esp = mip6_esm_find(bind_addr);
		if (esp == NULL) {
			log(LOG_ERR,
			    "%s: No event-state machine found\n",
			    __FUNCTION__);
			return IPPROTO_DONE;
		}

		/* If it's a de-registration, clear up the ESM. */
		if (esp->state == MIP6_STATE_DEREG) {
			/* Remove the tunnel for the MN */
			mip6_tunnel(NULL, NULL, MIP6_TUNNEL_DEL,
				    MIP6_NODE_MN, (void *)esp);

			/* Send BU to each entry (CN) in the BUL to remove
			   the BC entry. */
			mip6_update_cns(&esp->home_addr, &esp->home_addr,
					0, 0);
			mip6_outq_flush();

			/* Don't set the state until BUs have been sent
			   to all CNs, otherwise the Home Address option
			   will not be added for the outgoing packet. */
			esp->state = MIP6_STATE_HOME;
			esp->coa = in6addr_any;
			return 0;
		}

		/* If it's a registration, perform dynamic home agent address
		   discovery or use the existing. */
		if (esp->dad) {
			if (esp->dad->hal->len == IP6OPT_HALEN) {
				if (esp->dad->hal)
					_FREE(esp->dad->hal, M_TEMP);
				_FREE(esp->dad, M_TEMP);

				/* Build an anycast address */
				mip6_build_ha_anycast(&esp->ha_hn,
						      &esp->home_addr,
						      esp->prefix_len);
				if (IN6_IS_ADDR_UNSPECIFIED(&esp->ha_hn)) {
					log(LOG_ERR,
					    "%s: Could not create anycast "
					    "address for Mobile Node, "
					    "wrong prefix length\n",
					    __FUNCTION__);
					return IPPROTO_DONE;
				}
				dst_addr = &esp->ha_hn;
				lifetime = mip6_config.hr_lifetime;
			} else {
				dst_addr = &esp->dad->hal->halist[esp->dad->index];
				max_index = (esp->dad->hal->len / IP6OPT_HALEN) - 1;
				if (esp->dad->index == max_index)
					esp->dad->index = 0;
				else
					esp->dad->index += 1;
				lifetime = MIP6_BU_LIFETIME_DHAAD;
			}
		} else {
			/* Build an anycast address */
			mip6_build_ha_anycast(&esp->ha_hn, &esp->home_addr,
					      esp->prefix_len);
			if (IN6_IS_ADDR_UNSPECIFIED(&esp->ha_hn)) {
				log(LOG_ERR,
				    "%s: Could not create anycast address for Mobile "
				    "Node, wrong prefix length\n", __FUNCTION__);
				return IPPROTO_DONE;
			}
			dst_addr = &esp->ha_hn;
			lifetime = mip6_config.hr_lifetime;
		}

		/* Create a new BUL entry and send a BU to the Home Agent */
		bulp = mip6_bul_create(dst_addr, &esp->home_addr, &esp->coa,
				       lifetime, 1);
		if (bulp == NULL)
			return IPPROTO_DONE;

		bu_data.prefix_len = esp->prefix_len;
		bu_data.ack = 1;

		if (mip6_send_bu(bulp, &bu_data, NULL) != 0)
			return IPPROTO_DONE;
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_prefix_lifetime
 * Description: Decide the remaining valid lifetime for a home address. Search
 *              the prefix list for a match and use this lifetime value.
 * Note:        This function is used by the MN since no test of the on-link
 *              flag is done.
 * Ret value:   Lifetime
 ******************************************************************************
 */
u_int32_t
mip6_prefix_lifetime(addr)
struct in6_addr  *addr;  /* IPv6 address to check */
{
	struct nd_prefix  *pr;       /* Entries in the prexix list */
	u_int32_t         min_time;  /* Minimum life time */

	min_time = 0xffffffff;
	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		if (in6_are_prefix_equal(addr, &pr->ndpr_prefix.sin6_addr,
					 pr->ndpr_plen)) {
			return pr->ndpr_vltime;
		}
	}
	return min_time;
}



/*
 ******************************************************************************
 * Function:    mip6_create_retrans
 * Description: Removes the current content of the bulp->state variable and
 *              allocates new memory.
 * Ret value:   Pointer to the allocated memory or NULL.
 ******************************************************************************
 */
struct mip6_retrans *
mip6_create_retrans(bulp)
struct mip6_bul    *bulp;
{
	if (bulp == NULL)
		return NULL;

	mip6_clear_retrans(bulp);
	bulp->state = (struct mip6_retrans *)MALLOC(
		sizeof(struct mip6_retrans),
		M_TEMP, M_WAITOK);
	if (bulp->state == NULL)
		return NULL;
	bzero(bulp->state, sizeof(struct mip6_retrans));

	bulp->state->bu_opt = NULL;
	bulp->state->bu_subopt = NULL;
	bulp->state->ba_timeout = 2;
	bulp->state->time_left = 2;
	return bulp->state;
}



/*
 ******************************************************************************
 * Function:    mip6_clear_retrans
 * Description: Removes the current content of the bulp->state variable and
 *              sets it to NULL.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_clear_retrans(bulp)
struct mip6_bul    *bulp;
{
	if (bulp == NULL)
		return;

	if (bulp->state) {
		if (bulp->state->bu_opt)
			_FREE(bulp->state->bu_opt, M_TEMP);
		if (bulp->state->bu_subopt)
			_FREE(bulp->state->bu_subopt, M_TEMP);
		_FREE(bulp->state, M_TEMP);
		bulp->state = NULL;
	}
	return;
}



/*
 ##############################################################################
 #
 # LIST FUNCTIONS
 # The Mobile Node maintains a Bindig Update List (BUL) for each node to which
 # a BU has been sent.
 # Besides from this a list of event-state machines, one for each home address
 # is handled by the Mobile Node and the Correspondent Node since it may
 # become mobile at any time.
 # An output queue for piggybacking of options (BU, BA, BR) on the first
 # outgoing packet sent to the node is also maintained. If the option has not
 # been sent with a packet within MIP6_OUTQ_LIFETIME it will be sent in a
 # separate packet.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_bul_find
 * Description: Find a Binding Update List entry for which a matching can be
 *              found for both the destination and binding address.
 *              If variable dst_addr is NULL an entry for home registration
 *              will be searched for.
 * Ret value:   Pointer to Binding Update List entry or NULL
 ******************************************************************************
 */
struct mip6_bul *
mip6_bul_find(dst_addr, bind_addr)
struct in6_addr  *dst_addr;   /* Destination Address for Binding Update */
struct in6_addr  *bind_addr;  /* Home Address for MN or previous COA */
{
	struct mip6_bul  *bulp;   /* Entry in the Binding Update list */

	if (dst_addr == NULL) {
		for (bulp = mip6_bulq; bulp; bulp = bulp->next) {
			if (IN6_ARE_ADDR_EQUAL(bind_addr, &bulp->bind_addr) &&
			    (bulp->hr_flag))
				break;
		}
	} else {
		for (bulp = mip6_bulq; bulp; bulp = bulp->next) {
			if (IN6_ARE_ADDR_EQUAL(dst_addr, &bulp->dst_addr) &&
			    IN6_ARE_ADDR_EQUAL(bind_addr, &bulp->bind_addr))
				break;
		}
		if (bulp != NULL)
			return bulp;

		/* It might be that the dest address for the BU was the Home
		   Agent anycast address and in that case we try to find it. */
		for (bulp = mip6_bulq; bulp; bulp = bulp->next) {
			if ((bulp->dst_addr.s6_addr8[15] & 0x7f) ==
			    MIP6_ADDR_ANYCAST_HA &&
			    IN6_ARE_ADDR_EQUAL(bind_addr, &bulp->bind_addr)) {
				break;
			}
		}
	}
	return bulp;
}




/*
 ******************************************************************************
 * Function:    mip6_bul_create
 * Description: Create a new Binding Update List entry and insert it as the
 *              first entry in the list.
 * Ret value:   Pointer to Binding Update List entry or NULL.
 * Note:        If the BUL timeout function has not been started it is started.
 *              The BUL timeout function will be called once every second until
 *              there are no more entries in the BUL.
 ******************************************************************************
 */
struct mip6_bul *
mip6_bul_create(dst_addr, bind_addr, coa, lifetime, hr)
struct in6_addr      *dst_addr;   /* Dst address for Binding Update */
struct in6_addr      *bind_addr;  /* Home Address for MN or previous COA */
struct in6_addr      *coa;        /* Primary COA for MN */
u_int32_t             lifetime;   /* Lifetime for BU */
u_int8_t              hr;         /* Home registration flag */
{
	struct mip6_bul  *bulp;      /* New Binding Update list entry */
	int    s;

	bulp = (struct mip6_bul *)MALLOC(sizeof(struct mip6_bul),
					 M_TEMP, M_WAITOK);
	if (bulp == NULL)
		return NULL;
	bzero(bulp, sizeof(struct mip6_bul));

	bulp->next = NULL;
	bulp->dst_addr = *dst_addr;
	bulp->bind_addr = *bind_addr;
	bulp->coa = *coa;
	bulp->lifetime = lifetime;
	bulp->refreshtime = lifetime;
	bulp->seqno = 0;
	bulp->lasttime = 0;
	bulp->no_of_sent_bu = 0;
	bulp->state = NULL;
	bulp->bu_flag = 1;
	bulp->hr_flag = hr;
	bulp->update_rate = MIP6_MAX_UPDATE_RATE;

	/* Insert the entry as the first entry in the BUL. */
	s = splnet();
	if (mip6_bulq == NULL) {
		mip6_bulq = bulp;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_bul_handle =
#endif
			timeout(mip6_timer_bul, (void *)0, hz);
	} else {
		bulp->next = mip6_bulq;
		mip6_bulq = bulp;
	}
	splx(s);

#if MIP6_DEBUG
	mip6_debug("\nBinding Update List Entry created (0x%x)\n", bulp);
	mip6_debug("Destination Address: %s\n", ip6_sprintf(&bulp->dst_addr));
	mip6_debug("Binding Address:     %s\n", ip6_sprintf(&bulp->bind_addr));
	mip6_debug("Care-of Address:     %s\n", ip6_sprintf(&bulp->coa));
	mip6_debug("Life/Refresh time:   %u / %u\n", bulp->lifetime,
		   bulp->refreshtime);
	mip6_debug("Seq no/Home reg:     %u / ", bulp->seqno);
	if (bulp->hr_flag)
		mip6_debug("TRUE\n");
	else
		mip6_debug("FALSE\n");
#endif
	return bulp;
}



/*
 ******************************************************************************
 * Function:    mip6_bul_delete
 * Description: Delete the requested Binding Update list entry.
 * Ret value:   Ptr to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
struct mip6_bul *
mip6_bul_delete(bul_remove)
struct mip6_bul  *bul_remove;    /* BUL entry to be deleted */
{
	struct mip6_bul  *bulp;       /* Current entry in the BU list */
	struct mip6_bul  *bulp_prev;  /* Previous entry in the BU list */
	struct mip6_bul  *bulp_next;  /* Next entry in the BU list */
	int               s;

	/* Find the requested entry in the BUL. */
	s = splnet();
	bulp_next = NULL;
	bulp_prev = NULL;
	for (bulp = mip6_bulq; bulp; bulp = bulp->next) {
		bulp_next = bulp->next;
		if (bulp == bul_remove) {
			if (bulp_prev == NULL)
				mip6_bulq = bulp->next;
			else
				bulp_prev->next = bulp->next;
#if MIP6_DEBUG
			mip6_debug("\nBU List Entry deleted (0x%x)\n", bulp);
#endif
			mip6_clear_retrans(bulp);
			_FREE(bulp, M_TEMP);

			/* Remove the timer if the BUL queue is empty */
			if (mip6_bulq == NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
				untimeout(mip6_timer_bul, (void *)NULL,
					  mip6_timer_bul_handle);
				callout_handle_init(&mip6_timer_bul_handle);
#else
				untimeout(mip6_timer_bul, (void *)NULL);
#endif
			}
			break;
		}
		bulp_prev = bulp;
	}
	splx(s);
	return bulp_next;
}



/*
 ******************************************************************************
 * Function:    mip6_esm_find
 * Description: Find an event-state machine for which the Mobile Nodes home
 *              address matches and the type is correct.
 * Ret value:   Pointer to event-state machine entry or NULL
 ******************************************************************************
 */
struct mip6_esm *
mip6_esm_find(home_addr)
struct in6_addr  *home_addr;    /* MNs home address */
{
	struct mip6_esm  *esp;

	for (esp = mip6_esmq; esp; esp = esp->next) {
		if (IN6_ARE_ADDR_EQUAL(home_addr, &esp->home_addr))
			return esp;
	}
	return NULL;
}



/*
 ******************************************************************************
 * Function:    mip6_esm_create
 * Description: Create an event-state machine entry and add it first to the
 *              list. If type is PERMANENT the lifetime will be set to 0xFFFF,
 *              otherwise it will be set to the specified lifetime. If type is
 *              TEMPORARY the timer will be started if not already started.
 * Ret value:   Pointer to an event-state machine or NULL.
 ******************************************************************************
 */
struct mip6_esm *
mip6_esm_create(ifp, ha_hn, coa, home_addr, prefix_len, state,
                type, lifetime)
struct ifnet    *ifp;        /* Physical i/f used by this home address */
struct in6_addr *ha_hn;      /* Home agent address (home network) */
struct in6_addr *coa;        /* Current care-of address */
struct in6_addr *home_addr;  /* Home address */
u_int8_t         prefix_len; /* Prefix length for the home address */
int              state;      /* State of the home address */
enum esm_type    type;       /* Permanent or Temporary esm */
u_int16_t        lifetime;   /* Lifetime for event-state machine */
{
	struct mip6_esm  *esp, *esp_tmp;
	int               start_timer, s;

	esp = (struct mip6_esm *)MALLOC(sizeof(struct mip6_esm),
					M_TEMP, M_WAITOK);
	if (esp == NULL) {
		log(LOG_ERR,
		    "%s: Could not create an event-state machine\n",
		    __FUNCTION__);
		return NULL;
	}
	bzero(esp, sizeof(struct mip6_esm));

	esp->next = NULL;
	esp->ifp = ifp;
	esp->ep = NULL;
	esp->state = state;
	esp->type = type;
	esp->home_addr = *home_addr;
	esp->prefix_len = prefix_len;
	esp->ha_hn = *ha_hn;
	esp->coa = *coa;
	esp->ha_fn = NULL;
	esp->dad = NULL;

	if (type == PERMANENT) {
		esp->lifetime = 0xFFFF;
		start_timer = 0;
	} else {
		esp->lifetime = lifetime;
		start_timer = 1;
	}

	/* If no TEMPORARY already exist and the new is TEMPORARY, start
	   the timer. */
	for (esp_tmp = mip6_esmq; esp_tmp; esp_tmp = esp_tmp->next) {
		if (esp_tmp->type == TEMPORARY)
			start_timer = 0;
	}

	/* Insert entry as the first entry in the event-state machine list */
	s = splnet();
	if (mip6_esmq == NULL)
		mip6_esmq = esp;
	else {
		esp->next = mip6_esmq;
		mip6_esmq = esp;
	}
	splx(s);

	if (start_timer) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_esm_handle =
#endif
			timeout(mip6_timer_esm, (void *)0, hz);
	}
	return esp;
}



/*
 ******************************************************************************
 * Function:    mip6_esm_delete
 * Description: Delete the requested event-state machine.
 * Ret value:   Ptr to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
struct mip6_esm *
mip6_esm_delete(esm_remove)
struct mip6_esm  *esm_remove;    /* Event-state machine to be deleted */
{
	struct mip6_esm  *esp;       /* Current entry in event-state list */
	struct mip6_esm  *esp_prev;  /* Previous entry in event-state list */
	struct mip6_esm  *esp_next;  /* Next entry in the event-state list */
	int               s;

	/* Find the requested entry in the event-state list. */
	s = splnet();
	esp_next = NULL;
	esp_prev = NULL;
	for (esp = mip6_esmq; esp; esp = esp->next) {
		esp_next = esp->next;
		if (esp == esm_remove) {
			if (esp_prev == NULL)
				mip6_esmq = esp->next;
			else
				esp_prev->next = esp->next;

			mip6_tunnel(NULL, NULL, MIP6_TUNNEL_DEL, MIP6_NODE_MN,
				    (void *)esp);

			if (esp->dad) {
				if (esp->dad->hal)
					_FREE(esp->dad->hal, M_TEMP);
				_FREE(esp->dad, M_TEMP);
			}

			if (esp->ha_fn) {
				_FREE(esp->ha_fn, M_TEMP);
				esp->ha_fn = NULL;
			}

#if MIP6_DEBUG
			mip6_debug("\nEvent-state machine deleted (0x%x)\n",
				   esp);
#endif
			_FREE(esp, M_TEMP);

			/* Remove the timer if the ESM queue is empty */
			if (mip6_esmq == NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
				untimeout(mip6_timer_esm, (void *)NULL,
					  mip6_timer_esm_handle);
				callout_handle_init(&mip6_timer_esm_handle);
#else
				untimeout(mip6_timer_esm, (void *)NULL);
#endif
			}
			break;
		}
		esp_prev = esp;
	}
	splx(s);
	return esp_next;
}



/*
 ******************************************************************************
 * Function:    mip6_outq_create
 * Description: Add an entry to the output queue and store the destination
 *              option and the sub-option (if present) to this entry.
 * Ret value:   0 Everything is OK
 *              Otherwise appropriate error code
 * Note:        If the outqueue timeout function has not been started it is
 *              started. The outqueue timeout function will be called once
 *              every MIP6_OUTQ_INTERVAL second until there are no more entries
 *              in the list.
 ******************************************************************************
 */
int
mip6_outq_create(opt, subbuf, src_addr, dst_addr, flag)
void               *opt;       /* Destination option (BU, BR or BA) */
struct mip6_subbuf *subbuf;    /* Buffer containing destination sub-options */
struct in6_addr    *src_addr;  /* Source address for the option */
struct in6_addr    *dst_addr;  /* Destination address for the option */
enum send_state     flag;      /* Flag indicating the state of the entry */
{
	struct mip6_output  *outp;  /* Pointer to output list entry */
	int    s;

	outp = (struct mip6_output *)MALLOC(sizeof(struct mip6_output),
					    M_TEMP, M_WAITOK);
	if (outp == NULL)
		return ENOBUFS;
	bzero(outp, sizeof(struct mip6_output));

	outp->next = NULL;
	outp->opt = opt;
	outp->subopt = subbuf;
	outp->ip6_dst = *dst_addr;
	outp->ip6_src = *src_addr;
	outp->flag = flag;
	outp->lifetime = MIP6_OUTQ_LIFETIME;

	s = splnet();
	if (mip6_outq == NULL) {
		mip6_outq = outp;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_outqueue_handle =
#endif
			timeout(mip6_timer_outqueue, (void *)0,
				hz * (MIP6_OUTQ_INTERVAL/10));
	} else {
		/* Add this entry as the first entry in the queue. */
		outp->next = mip6_outq;
		mip6_outq = outp;
	}
	splx(s);
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_outq_delete
 * Description: Delete the requested output queue entry.
 * Ret value:   Ptr to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
struct mip6_output *
mip6_outq_delete(oqp_remove)
struct mip6_output  *oqp_remove;    /* Output queue entry to be deleted */
{
	struct mip6_output  *oqp;       /* Current entry in output queue */
	struct mip6_output  *oqp_prev;  /* Previous entry in output queue */
	struct mip6_output  *oqp_next;  /* Next entry in the output queue */
	int    s;

	/* Find the requested entry in the output queue. */
	s = splnet();
	oqp_next = NULL;
	oqp_prev = NULL;
	for (oqp = mip6_outq; oqp; oqp = oqp->next) {
		oqp_next = oqp->next;
		if (oqp == oqp_remove) {
			if (oqp_prev == NULL)
				mip6_outq = oqp->next;
			else
				oqp_prev->next = oqp->next;

			if (oqp->opt)
				_FREE(oqp->opt, M_TEMP);

			if (oqp->subopt)
				_FREE(oqp->subopt, M_TEMP);

#if MIP6_DEBUG
			mip6_debug("\nOutput Queue entry deleted (0x%x)\n",
				   oqp);
#endif
			_FREE(oqp, M_TEMP);

			/* Remove the timer if the output queue is empty */
			if (mip6_outq == NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
				untimeout(mip6_timer_outqueue, (void *)NULL,
					  mip6_timer_outqueue_handle);
				callout_handle_init(
					&mip6_timer_outqueue_handle);
#else
				untimeout(mip6_timer_outqueue, (void *)NULL);
#endif
			}
			break;
		}
		oqp_prev = oqp;
	}
	splx(s);
	return oqp_next;
}



/*
 ******************************************************************************
 * Function:    mip6_outq_flush
 * Description: All entries in the output queue that have not been sent are
 *              sent and then removed. No consideration of the time left for
 *              the entry is taken.
 * Ret value:   -
 * XXX          The code is almost the same as in mip6_timer_outqueue
 ******************************************************************************
 */
void
mip6_outq_flush()
{
	struct mip6_output  *outp;   /* Ptr to current mip6 output element */
	struct ip6_pktopts  *pktopt; /* Packet Ext headers, options and data */
	struct mip6_opt     *opt;    /* Destination option */
	struct mbuf         *m_ip6;  /* IPv6 header stored in a mbuf */
	int                 error;   /* Error code from function call */
	int                 off;     /* Offset from start of DH (byte) */
	int    s;

	/* Go through the entire output queue and send all packets that
	   have not been sent. */
	s = splnet();
	for (outp = mip6_outq; outp;) {
		if (outp->flag == NOT_SENT) {
			m_ip6 = mip6_create_ip6hdr(&outp->ip6_src,
						   &outp->ip6_dst,
						   IPPROTO_NONE);
			if (m_ip6 == NULL) {
				outp = outp->next;
				continue;
			}

			/* Allocate packet extension header. */
			pktopt = (struct ip6_pktopts *)
				MALLOC(sizeof(struct ip6_pktopts),
				       M_TEMP, M_WAITOK);
			if (pktopt == NULL) {
				_FREE(m_ip6, M_TEMP);
				outp = outp->next;
				continue;
			}
			bzero(pktopt, sizeof(struct ip6_pktopts));
			pktopt->ip6po_hlim = -1;  /* -1 use def hop limit */

			opt = (struct mip6_opt *)outp->opt;
			off = 2;
			if (opt->type == IP6OPT_BINDING_UPDATE) {
				/* Add my BU option to the Dest Header */
				error = mip6_add_bu(&pktopt->ip6po_dest2,
						    &off,
						    (struct mip6_opt_bu *)
						    outp->opt,
						    outp->subopt);
				if (error) {
					_FREE(m_ip6, M_TEMP);
					_FREE(pktopt, M_TEMP);
					outp = outp->next;
					continue;
				}
			} else if (opt->type == IP6OPT_BINDING_ACK) {
				/* Add my BA option to the Dest Header */
				error = mip6_add_ba(&pktopt->ip6po_dest2,
						    &off,
						    (struct mip6_opt_ba *)
						    outp->opt,
						    outp->subopt);
				if (error) {
					_FREE(m_ip6, M_TEMP);
					_FREE(pktopt, M_TEMP);
					outp = outp->next;
					continue;
				}
			} else if (opt->type == IP6OPT_BINDING_REQ) {
				/* Add my BR option to the Dest Header */
				error = mip6_add_br(&pktopt->ip6po_dest2,
						    &off,
						    (struct mip6_opt_br *)
						    outp->opt,
						    outp->subopt);
				if (error) {
					_FREE(m_ip6, M_TEMP);
					_FREE(pktopt, M_TEMP);
					outp = outp->next;
					continue;
				}
			}

			/* Disable the search of the output queue to make
			   sure that we not end up in an infinite loop. */
			mip6_config.enable_outq = 0;
			error = ip6_output(m_ip6, pktopt, NULL, 0, NULL, NULL);
			if (error) {
				_FREE(m_ip6, M_TEMP);
				_FREE(pktopt, M_TEMP);
				mip6_config.enable_outq = 1;
				outp = outp->next;
				log(LOG_ERR,
				    "%s: ip6_output function failed, "
				    "error = %d\n", __FUNCTION__, error);
				continue;
			}
			mip6_config.enable_outq = 1;
			outp->flag = SENT;
#if MIP6_DEBUG
			mip6_debug("\nEntry from Output Queue sent\n");
#endif
		}

		/* Remove entry from the queue that has been sent. */
		if (outp->flag == SENT)
			outp = mip6_outq_delete(outp);
		else
			outp = outp->next;

		/* Remove the timer if the output queue is empty */
		if (mip6_outq == NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
			untimeout(mip6_timer_outqueue, (void *)NULL,
				  mip6_timer_outqueue_handle);
			callout_handle_init(&mip6_timer_outqueue_handle);
#else
			untimeout(mip6_timer_outqueue, (void *)NULL);
#endif
		}
	}
	splx(s);
}



/*
 ##############################################################################
 #
 # TIMER FUNCTIONS
 # These functions are called at regular basis. They operate on the lists, e.g.
 # reducing timer counters and removing entries from the list if needed.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_timer_outqueue
 * Description: Search the outqueue for entries that have not been sent yet and
 *              for which the lifetime has expired.
 *              If there are more entries left in the output queue, call this
 *              fuction again every MIP6_OUTQ_INTERVAL until the queue is
 *              empty.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_outqueue(arg)
void  *arg;  /* Not used */
{
	struct mip6_output  *outp;   /* Ptr to current mip6 output element */
	struct ip6_pktopts  *pktopt; /* Packet Ext headers, options and data */
	struct mip6_opt     *opt;    /* Destination option */
	struct mbuf         *m_ip6;  /* IPv6 header stored in a mbuf */
	int                 error;   /* Error code from function call */
	int                 off;     /* Offset from start of DH (byte) */

#ifdef __APPLE__
	boolean_t   funnel_state;
    	funnel_state = thread_set_funneled(TRUE);
#endif
	/* Go through the entire output queue and send all packets that
	   have not been sent. */
	for (outp = mip6_outq; outp;) {
		if (outp->flag == NOT_SENT)
			outp->lifetime -= MIP6_OUTQ_INTERVAL;

		if ((outp->flag == NOT_SENT) && (outp->lifetime <= 0)) {
			m_ip6 = mip6_create_ip6hdr(&outp->ip6_src,
						   &outp->ip6_dst,
						   IPPROTO_NONE);
			if (m_ip6 == NULL) {
				outp = outp->next;
				continue;
			}

			/* Allocate packet extension header. */
			pktopt = (struct ip6_pktopts *)
				MALLOC(sizeof(struct ip6_pktopts),
				       M_TEMP, M_WAITOK);
			if (pktopt == NULL) {
				_FREE(m_ip6, M_TEMP);
				outp = outp->next;
				continue;
			}
			bzero(pktopt, sizeof(struct ip6_pktopts));
			pktopt->ip6po_hlim = -1;  /* -1 default hop limit */

			opt = (struct mip6_opt *)outp->opt;
			off = 2;
			if (opt->type == IP6OPT_BINDING_UPDATE) {
				/* Add my BU option to the Dest Header */
				error = mip6_add_bu(&pktopt->ip6po_dest2,
						    &off,
						    (struct mip6_opt_bu *)
						    outp->opt,
						    outp->subopt);
				if (error) {
					_FREE(m_ip6, M_TEMP);
					_FREE(pktopt, M_TEMP);
					outp = outp->next;
					continue;
				}
			} else if (opt->type == IP6OPT_BINDING_ACK) {
				/* Add my BA option to the Dest Header */
				error = mip6_add_ba(&pktopt->ip6po_dest2,
						    &off,
						    (struct mip6_opt_ba *)
						    outp->opt,
						    outp->subopt);
				if (error) {
					_FREE(m_ip6, M_TEMP);
					_FREE(pktopt, M_TEMP);
					outp = outp->next;
					continue;
				}
			} else if (opt->type == IP6OPT_BINDING_REQ) {
				/* Add my BR option to the Dest Header */
				error = mip6_add_br(&pktopt->ip6po_dest2,
						    &off,
						    (struct mip6_opt_br *)
						    outp->opt,
						    outp->subopt);
				if (error) {
					_FREE(m_ip6, M_TEMP);
					_FREE(pktopt, M_TEMP);
					outp = outp->next;
					continue;
				}
			}

			/* Disable the search of the output queue to make
			   sure that we not end up in an infinite loop. */
			mip6_config.enable_outq = 0;
			error = ip6_output(m_ip6, pktopt, NULL, 0, NULL, NULL);
			if (error) {
				_FREE(m_ip6, M_TEMP);
				_FREE(pktopt, M_TEMP);
				mip6_config.enable_outq = 1;
				outp = outp->next;
				log(LOG_ERR,
				    "%s: ip6_output function failed, "
				    "error = %d\n", __FUNCTION__, error);
				continue;
			}
			mip6_config.enable_outq = 1;
			outp->flag = SENT;
#if MIP6_DEBUG
			mip6_debug("\nEntry from Output Queue sent\n");
#endif
		}

		/* Remove entry from the queue that has been sent. */
		if (outp->flag == SENT)
			outp = mip6_outq_delete(outp);
		else
			outp = outp->next;
	}

	if (mip6_outq != NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_outqueue_handle =
#endif
			timeout(mip6_timer_outqueue, (void *)0,
				hz * (MIP6_OUTQ_INTERVAL/10));
	}
#ifdef __APPLE__
    (void) thread_set_funneled(funnel_state);
#endif
}



/*
 ******************************************************************************
 * Function:    mip6_timer_bul
 * Description: Search the Binding Update list for entries for which the life-
 *              time or refresh time has expired.
 *              If there are more entries left in the output queue, call this
 *              fuction again once every second until the queue is empty.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_bul(arg)
void  *arg;   /* Not used */
{
	struct mip6_bul        *bulp;      /* Ptr to current BUL element */
	struct mip6_bul        *new_bulp;  /* Pointer to new BUL entry */
	struct mip6_esm        *esp;       /* Home address entry */
	struct mip6_opt_bu     *bu_opt;    /* BU option to be sent */
	struct in6_addr        *dst_addr;  /* Destination address for BU */
	struct mip6_subbuf     *subbuf;    /* Buffer containing sub-options */
	struct mip6_bu_data     bu_data;   /* Data used when a BU is created */
	struct mip6_subopt_coa  altcoa;    /* Alternate care-of address */
	u_int32_t               lifetime;
	int                     max_index, s;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif
#ifdef __APPLE__
	boolean_t   funnel_state;
    	funnel_state = thread_set_funneled(TRUE);
#endif

	/* Go through the entire BUL and check if any BU have to be sent. */
	subbuf = NULL;
	s = splnet();
	for (bulp = mip6_bulq; bulp;) {
		/* Find the correct event-state machine */
		esp = mip6_esm_find(&bulp->bind_addr);
		if (esp == NULL) {
			bulp = bulp->next;
			continue;
		}

		/* If infinity lifetime, don't decrement it. */
		if (bulp->lifetime == 0xffffffff) {
			bulp = bulp->next;
			continue;
		}

		bulp->lifetime -= 1;
		if (bulp->lifetime == 0) {
			if ((bulp->hr_flag) && (esp->type == PERMANENT)) {
				/* If this BUL entry is for the Home Agent
				   a new one must be created before the old
				   is deleted. The new entry shall try to
				   register the MN again.
				   This is not done for the previous default
				   router. */
				if ((esp->state == MIP6_STATE_REG) ||
				    (esp->state == MIP6_STATE_REREG) ||
				    (esp->state == MIP6_STATE_REGNEWCOA) ||
				    (esp->state == MIP6_STATE_NOTREG))
					esp->state = MIP6_STATE_NOTREG;
				else if ((esp->state == MIP6_STATE_HOME) ||
					 (esp->state == MIP6_STATE_DEREG))
					esp->state = MIP6_STATE_DEREG;
				else
					esp->state = MIP6_STATE_UNDEF;

				/* If Dynamic Home Agent Address Discovery,
				   pick the dst address from the esp->dad list
				   and set index. */
				if (esp->dad) {
					dst_addr = &esp->dad->hal->
						halist[esp->dad->index];
					max_index = (esp->dad->hal->len /
						     IP6OPT_HALEN) - 1;
					if (esp->dad->index == max_index)
						esp->dad->index = 0;
					else
						esp->dad->index += 1;
					lifetime = MIP6_BU_LIFETIME_DHAAD;
				} else {
					dst_addr = &esp->ha_hn;
					lifetime = mip6_config.hr_lifetime;
				}

				/* Send BU to the decided destination */
				new_bulp = mip6_bul_create(dst_addr,
							   &esp->home_addr,
							   &bulp->coa,
							   lifetime, 1);
				if (new_bulp == NULL)
					break;

				bu_data.prefix_len = esp->prefix_len;
				bu_data.ack = 1;

				if (mip6_send_bu(new_bulp, &bu_data, NULL)
				    != 0)
					break;
			}

			/* The BUL entry must be deleted. */
			bulp = mip6_bul_delete(bulp);
			continue;
		}

		if (bulp->refreshtime > 0)
			bulp->refreshtime -= 1;

		/* Skip the bul entry if its not allowed to send any further
		   BUs to the host. */
		if (bulp->bu_flag == 0) {
			bulp = bulp->next;
			continue;
		}

		/* Check if a BU has already been sent to the destination. */
		if (bulp->state != NULL) {
			bulp->state->time_left -= 1;
			if (bulp->state->time_left == 0) {
				if (bulp->hr_flag) {
					/* This is a BUL entry for the HA */
					bulp->state->bu_opt->lifetime =
						bulp->lifetime;
					bulp->state->bu_opt->seqno++;
					if (mip6_send_bu(bulp, NULL, NULL)
					    != 0)
						break;

					if (bulp->state->ba_timeout <
					    MIP6_MAX_BINDACK_TIMEOUT)
						bulp->state->ba_timeout =
							2 * bulp->state->
							ba_timeout;
					else
						bulp->state->ba_timeout =
							(u_int8_t)MIP6_MAX_BINDACK_TIMEOUT;

					bulp->state->time_left = bulp->state->ba_timeout;
				} else {
					/* This is a BUL entry for a Correspondent Node */
					if (bulp->state->ba_timeout >= MIP6_MAX_BINDACK_TIMEOUT) {
						/* Do NOT continue to retransmit the BU */
						bulp->no_of_sent_bu = 0;
						mip6_clear_retrans(bulp);
					} else {
						bulp->state->bu_opt->lifetime = bulp->lifetime;
						bulp->state->bu_opt->seqno++;
						if (mip6_send_bu(bulp, NULL, NULL) != 0)
							break;
						
						bulp->state->ba_timeout = 2 * bulp->state->ba_timeout;
						bulp->state->time_left = bulp->state->ba_timeout;
					}
				}
			}
			bulp = bulp->next;
			continue;
		}
		
		/* Refreshtime has expired and no BU has been sent to the HA
		   so far. Then we do it. */
		if (bulp->refreshtime == 0) {
			/* Store sub-option for BU option. */
			altcoa.type = IP6SUBOPT_ALTCOA;
			altcoa.len = IP6OPT_COALEN;
			altcoa.coa = bulp->coa;
			if (mip6_store_subopt(&subbuf, (caddr_t)&altcoa)) {
				if (subbuf)
					_FREE(subbuf, M_TEMP);
				break;
			}

			if (bulp->hr_flag) {
				/* Since this is an entry for the Home Agent a new BU
				   is being sent for which we require the receiver to
				   respond with a BA. */
				bu_data.prefix_len = esp->prefix_len;
				bu_data.ack = 1;
				
				bulp->lifetime = mip6_config.hr_lifetime;
				if (mip6_send_bu(bulp, &bu_data, subbuf) != 0)
					break;
			} else {
				/* This is an entry for a CN that has requested a BU to be
				   sent when the refreshtime expires. We will NOT require
				   this BU to be acknowledged. */
				bulp->seqno += 1;
				bu_opt = mip6_create_bu(0, 0, 0, bulp->seqno,
							mip6_config.hr_lifetime);
				if (bu_opt == NULL)
					break;
				
				bulp->lasttime = time_second;
				mip6_outq_create(bu_opt, subbuf, &bulp->bind_addr,
						 &bulp->dst_addr, NOT_SENT);
			}
			bulp = bulp->next;
			continue;
		}
		bulp = bulp->next;
	}
	
	if (mip6_bulq != NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_bul_handle =
#endif
			timeout(mip6_timer_bul, (void *)0, hz);
	}
	splx(s);
#ifdef __APPLE__
	(void) thread_set_funneled(funnel_state);
#endif
}



/*
 ******************************************************************************
 * Function:    mip6_timer_esm
 * Description: This function is called when an event-state machine has been
 *              created for sending a BU to the previous default router. The
 *              event-state machine entry is needed for the correct addition
 *              of the home address option for outgoing packets.
 *              When the life time for the BU expires the event-state machine
 *              is removed as well.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_esm(arg)
void  *arg;  /* Not used */
{
	struct mip6_esm  *esp;       /* Current event-state machine entry */
	int              s, start_timer;
#ifdef __APPLE__
    	boolean_t   funnel_state;
    	funnel_state = thread_set_funneled(TRUE);
#endif
	
	/* Go through the entire list of event-state machines. */
	s = splnet();
	for (esp = mip6_esmq; esp;) {
		if (esp->type == TEMPORARY) {
			esp->lifetime -= 1;
			
			if (esp->lifetime == 0)
				esp = mip6_esm_delete(esp);
            else
		    esp = esp->next;
			continue;
		}
		esp = esp->next;
	}
	
	/* Only start the timer if there is a TEMPORARY machine in the list. */
	start_timer = 0;
	for (esp = mip6_esmq; esp; esp = esp->next) {
		if (esp->type == TEMPORARY) {
			start_timer = 1;
			break;
		}
	}
	
	if (start_timer) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_esm_handle =
#endif
			timeout(mip6_timer_esm, (void *)0, hz);
	}
	splx(s);
#ifdef __APPLE__
    	(void) thread_set_funneled(funnel_state);
#endif
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
 * Function:    mip6_write_config_data_mn
 * Description: This function is called to write certain config values for
 *              MIPv6. The data is written into the global config structure.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_write_config_data_mn(u_long cmd, void *arg)
{
	struct mip6_esm         *p;
	struct ifnet            *ifp;
	struct mip6_input_data  *input;
	struct mip6_static_addr *np;
	char                     ifn[10];
	int                      retval = 0;
	struct in6_addr          any = in6addr_any;

	switch (cmd) {
	case SIOCACOADDR_MIP6:
		input = (struct mip6_input_data *) arg;
		np = (struct mip6_static_addr *)
			MALLOC(sizeof(struct mip6_static_addr),
			       M_TEMP, M_WAITOK);
		if (np == NULL)
			return ENOBUFS;

		np->ip6_addr = input->ip6_addr;
		np->prefix_len = input->prefix_len;
		np->ifp = ifunit(input->if_name);
		if (np->ifp == NULL) {
			strncpy(ifn, input->if_name, sizeof(ifn));
			return EINVAL;
		}
		LIST_INSERT_HEAD(&mip6_config.fna_list, np, addr_entry);
		break;

	case SIOCAHOMEADDR_MIP6:
		input = (struct mip6_input_data *) arg;
		ifp = ifunit(input->if_name);
		if (ifp == NULL)
			return EINVAL;

		p = mip6_esm_create(ifp, &input->ha_addr, &any,
				    &input->ip6_addr, input->prefix_len,
				    MIP6_STATE_UNDEF, PERMANENT, 0xFFFF);
		if (p == NULL)
			return EINVAL;	/*XXX*/

		break;

	case SIOCSBULIFETIME_MIP6:
		mip6_config.bu_lifetime = ((struct mip6_input_data *)arg)->value;
		break;

	case SIOCSHRLIFETIME_MIP6:
		mip6_config.hr_lifetime = ((struct mip6_input_data *)arg)->value;
		break;

	case SIOCDCOADDR_MIP6:
		input = (struct mip6_input_data *) arg;
		for (np = mip6_config.fna_list.lh_first; np != NULL;
		     np = np->addr_entry.le_next){
			if (IN6_ARE_ADDR_EQUAL(&input->ip6_addr, &np->ip6_addr))
				break;
		}
		if (np == NULL){
			retval = EADDRNOTAVAIL;
			return retval;
		}
		LIST_REMOVE(np, addr_entry);
		break;
	}
	return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_clear_config_data_mn
 * Description: This function is called to clear internal lists handled by
 *              MIPv6.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_clear_config_data_mn(u_long cmd, caddr_t data)
{
	int retval = 0;
	int s;

	struct mip6_static_addr *np;
	struct mip6_bul         *bulp;

	s = splnet();
	switch (cmd) {
	case SIOCSFORADDRFLUSH_MIP6:
		for (np = LIST_FIRST(&mip6_config.fna_list); np;
		     np = LIST_NEXT(np, addr_entry)) {
			LIST_REMOVE(np, addr_entry);
		}
		break;

	case SIOCSHADDRFLUSH_MIP6:
		retval = EINVAL;
		break;

	case SIOCSBULISTFLUSH_MIP6:
		for (bulp = mip6_bulq; bulp;)
			bulp = mip6_bul_delete(bulp);
		break;
	}
	splx(s);
	return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_enable_func_mn
 * Description: This function is called to enable or disable certain functions
 *              in mip6. The data is written into the global config struct.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_enable_func_mn(u_long cmd, caddr_t data)
{
	int enable;
	int retval = 0;

	enable = ((struct mip6_input_data *)data)->value;

	switch (cmd) {
	case SIOCSPROMMODE_MIP6:
		mip6_config.enable_prom_mode = enable;
		break;

	case SIOCSBU2CN_MIP6:
		mip6_config.enable_bu_to_cn = enable;
		break;

	case SIOCSREVTUNNEL_MIP6:
		mip6_config.enable_rev_tunnel = enable;
		break;

	case SIOCSAUTOCONFIG_MIP6:
		mip6_config.autoconfig = enable;
		break;

	case SIOCSEAGERMD_MIP6:
		mip6_eager_md(enable);
		break;
	}
	return retval;
}
