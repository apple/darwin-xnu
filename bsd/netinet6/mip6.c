/*	$KAME: mip6.c,v 1.20 2000/03/18 03:05:38 itojun Exp $	*/

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
 *         Mattias Pettersson <mattias.pettersson@era.ericsson.se>
 *
 */

/*
 * TODO: nuke calls to in6_control, it is not supposed to be called from
 * softintr
 */

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#endif

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
#include <net/if_gif.h>
#include <net/if_dl.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip_encap.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6protosw.h>

#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>

#if MIP6_DEBUG
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <machine/stdarg.h>
#include <sys/syslog.h>
#endif

#include <net/net_osdep.h>

int  (*mip6_rec_ra_hook)(struct mbuf *, int) = 0;

struct in6_addr * (*mip6_global_addr_hook)(struct in6_addr *) = 0;
struct mip6_subopt_hal * (*mip6_hal_dynamic_hook)(struct in6_addr *) = 0;
int  (*mip6_write_config_data_ha_hook)(u_long, void *) = 0;
int  (*mip6_clear_config_data_ha_hook)(u_long, void *) = 0;
int  (*mip6_enable_func_ha_hook)(u_long, caddr_t) = 0;

int  (*mip6_rec_ba_hook)(struct mbuf *, int) = 0;
int  (*mip6_rec_br_hook)(struct mbuf *, int) = 0;
void (*mip6_stop_bu_hook)(struct in6_addr *) = 0;
int  (*mip6_write_config_data_mn_hook)(u_long, void *) = 0;
int  (*mip6_clear_config_data_mn_hook)(u_long, caddr_t) = 0;
int  (*mip6_enable_func_mn_hook)(u_long, caddr_t) = 0;


#if MIP6_DEBUG
int mip6_debug_is_enabled = 0;
#endif


/* Declaration of Global variables. */
struct mip6_bc     *mip6_bcq = NULL;  /* First entry in BC list */
struct mip6_na     *mip6_naq = NULL;  /* First entry in NA retrans. list */
struct mip6_prefix *mip6_pq = NULL;   /* Ptr to prefix queue */
struct mip6_config  mip6_config;      /* Config parameters for MIPv6 */
struct mip6_link_list  *mip6_llq = NULL;  /* List of links receiving RA's */


#if 0  /* Phasing out MIP6_HA and MIP6_MN */
#if MIP6_HA
u_int8_t mip6_module = MIP6_HA_MODULE;  /* Info about loaded modules (HA) */
#elif defined(MIP6_MN)
u_int8_t mip6_module = MIP6_MN_MODULE;  /* Info about loaded modules (MN) */
#else
u_int8_t mip6_module = 0;               /* Info about loaded modules (CN) */
#endif
#else /* 0 */
u_int8_t mip6_module = 0;               /* Info about loaded modules (CN) */
#endif /* 0 */

extern struct ip6protosw mip6_tunnel_protosw;


#if defined(__FreeBSD__) && __FreeBSD__ >= 3
struct callout_handle  mip6_timer_na_handle;
struct callout_handle  mip6_timer_bc_handle;
struct callout_handle  mip6_timer_prefix_handle;
#endif


/* Definitions of some costant IP6 addresses. */
struct in6_addr in6addr_linklocal;
struct in6_addr in6addr_sitelocal;
struct in6_addr in6addr_aha_64;
struct in6_addr in6addr_aha_nn;


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
 * Function:    mip6_init
 * Description: Initialization of MIPv6 variables that must be initialized
 *              before the code is executed.
 ******************************************************************************
 */
void
mip6_init(void)
{
	static int mip6_init_done = 0;

	if (mip6_init_done)
		return;

	/* Initialize global addresses. */
	in6addr_linklocal.s6_addr32[0] = MIP6_ADDR_INT32_ULL;
	in6addr_linklocal.s6_addr32[1] = 0x00000000;
	in6addr_linklocal.s6_addr32[2] = 0x00000000;
	in6addr_linklocal.s6_addr32[3] = 0x00000000;

	in6addr_sitelocal.s6_addr32[0] = MIP6_ADDR_INT32_USL;
	in6addr_sitelocal.s6_addr32[1] = 0x00000000;
	in6addr_sitelocal.s6_addr32[2] = 0x00000000;
	in6addr_sitelocal.s6_addr32[3] = 0x00000000;

	in6addr_aha_64.s6_addr32[0] = 0x00000000;
	in6addr_aha_64.s6_addr32[1] = 0xffffffff;
	in6addr_aha_64.s6_addr32[2] = MIP6_ADDR_INT32_AHA2;
	in6addr_aha_64.s6_addr32[3] = MIP6_ADDR_INT32_AHA1;

	in6addr_aha_nn.s6_addr32[0] = 0x00000000;
	in6addr_aha_nn.s6_addr32[1] = 0xffffffff;
	in6addr_aha_nn.s6_addr32[2] = 0xffffffff;
	in6addr_aha_nn.s6_addr32[3] = MIP6_ADDR_INT32_AHA1;

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	/* Initialize handle for timer functions. */
	callout_handle_init(&mip6_timer_na_handle);
	callout_handle_init(&mip6_timer_bc_handle);
	callout_handle_init(&mip6_timer_prefix_handle);
#endif

	/* Initialize global variable */
	bzero(&mip6_config, sizeof(struct mip6_config));

	/* Set default values for MIP6 configuration parameters. */
	LIST_INIT(&mip6_config.fna_list);

	mip6_config.bu_lifetime = 600;
	mip6_config.br_update = 60;
	mip6_config.hr_lifetime = 3600;
	mip6_config.enable_outq = 1;

	mip6_enable_hooks(MIP6_GENERIC_HOOKS);
	mip6_enable_hooks(MIP6_CONFIG_HOOKS);

	mip6_init_done = 1;
	printf("%s: MIP6 initialized\n", __FUNCTION__);
}



/*
 ******************************************************************************
 * Function:    mip6_exit
 * Description: This function is called when the module is unloaded (relesed)
 *              from the kernel.
 ******************************************************************************
 */
void
mip6_exit()
{
	struct mip6_na     *nap, *nap_tmp;
	struct mip6_bc     *bcp, *bcp_nxt;
	struct mip6_prefix *prefix;
	int                 s;

	/* Cancel outstanding timeout function calls. */
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	untimeout(mip6_timer_na, (void *)NULL, mip6_timer_na_handle);
	untimeout(mip6_timer_bc, (void *)NULL , mip6_timer_bc_handle);
	untimeout(mip6_timer_prefix, (void *)NULL, mip6_timer_prefix_handle);
#else
	untimeout(mip6_timer_na, (void *)NULL);
	untimeout(mip6_timer_bc, (void *)NULL);
	untimeout(mip6_timer_prefix, (void *)NULL);
#endif

	/* Remove each entry in every queue. */
	s = splnet();
	for (nap = mip6_naq; nap;) {
		nap_tmp = nap;
		nap = nap->next;
		_FREE(nap_tmp, M_TEMP);
	}
	mip6_naq = NULL;

	for (bcp = mip6_bcq; bcp;) {
		mip6_bc_delete(bcp, &bcp_nxt);
		bcp = bcp_nxt;
	}
	mip6_bcq = NULL;

	for (prefix = mip6_pq; prefix;)
		prefix = mip6_prefix_delete(prefix);
	mip6_pq = NULL;
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
 * Function:    mip6_rec_ctrl_sig
 * Description: This function receives incoming signals and calls the approp-
 *              riate function for further processing of the destination
 *              option.
 * Ret value:   0             Everything is OK.
 *              IPPROTO_DONE  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_rec_ctrl_sig(m_in, off)
struct mbuf *m_in;  /* Mbuf containing the entire IPv6 packet */
int         off;    /* Offset (bytes) from beginning of mbuf to start of
                       destination option */
{
	register struct ip6_hdr *ip6;  /* IPv6 header */
	int                      res;  /* Result of function call */

#if MIP6_DEBUG
	static int  count = 0;

	count += 1;
	mip6_debug("\nMIPv6 Start processing a control signal (%d)\n", count);
#endif

	res = 0;
	if (mip6_inp == NULL) {
		log(LOG_ERR, "%s: Variabel mip6_inp is NULL\n",
		    __FUNCTION__);
		return IPPROTO_DONE;
	}
	ip6 = mtod(m_in, struct ip6_hdr *);

	/* Store necessary data from IPv6 header */
	mip6_inp->ip6_src = ip6->ip6_src;
	mip6_inp->ip6_dst = ip6->ip6_dst;

	/* Process incoming signal (BU, BA, BR and/or Home Address option) */
	if (mip6_inp->optflag & MIP6_DSTOPT_BU) {
		res = mip6_rec_bu(m_in, off);
		if (res != 0) {
#if MIP6_DEBUG
			mip6_debug("\nMIPv6 Error processing control "
				   "signal BU (%d)\n", count);
#endif
			return res;
		}
	}

	if (MIP6_IS_MN_ACTIVE) {
		if (mip6_inp->optflag & MIP6_DSTOPT_BA) {
			if (mip6_rec_ba_hook)
				res = (*mip6_rec_ba_hook)(m_in, off);
			if (res != 0) {
#if MIP6_DEBUG
				mip6_debug("\nMIPv6 Error processing control "
					   "signal BA (%d)\n", count);
#endif
				return res;
			}
		}
	}

	if (MIP6_IS_MN_ACTIVE) {
		if (mip6_inp->optflag & MIP6_DSTOPT_BR) {
			if (mip6_rec_br_hook)
				res = (*mip6_rec_br_hook)(m_in, off);
			if (res != 0) {
#if MIP6_DEBUG
				mip6_debug("\nMIPv6 Error processing control "
					   "signal BR (%d)\n", count);
#endif
				return res;
			}
		}
	}

	if (mip6_inp->optflag & MIP6_DSTOPT_HA)
		mip6_ha2srcaddr(m_in);

#if MIP6_DEBUG
	mip6_debug("\nMIPv6 Finished processing a control signal (%d)\n",
		   count);
#endif
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_icmp6_input
 * Description: Every ICMP6 message must be checked for errors. If a Router
 *              Advertisement is included the Home Agent List must be up-
 *              dated.
 *              The check of the Router Advertisement can not be done in
 *              function nd6_ra_input since this function only deals with
 *              configuration issues.
 * Ret value:   0             Everything is OK.
 *              IPPROTO_DONE  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_icmp6_input(m, off)
struct mbuf *m;     /* Mbuf containing the entire IPv6 packet */
int          off;   /* Offset from start of mbuf to icmp6 message */
{
	struct ip6_hdr           *ip6;      /* IPv6 header */
	struct ip6_hdr           *ip6_icmp; /* IPv6 header in icmpv6 packet */
	struct icmp6_hdr         *icmp6;    /* ICMP6 header */
	struct mip6_bc           *bcp;      /* Binding Cache list entry */
	struct mip6_bc           *bcp_nxt;  /* Binding Cache list entry */
	struct nd_router_advert  *ra;       /* Router Advertisement */
	u_int8_t    *err_ptr;               /* Octet offset for error */
	int          icmp6len, err_off, res = 0;

	ip6 = mtod(m, struct ip6_hdr *);
	icmp6len = m->m_pkthdr.len - off;
	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		/* First we have to find the destination address
		   from the original IPv6 packet. Make sure that
		   the IPv6 packet is included in the ICMPv6 packet. */
		if ((off + sizeof(struct icmp6_hdr) +
		     sizeof(struct ip6_hdr)) >= m->m_pkthdr.len)
			return 0;

		ip6_icmp = (struct ip6_hdr *) ((caddr_t)icmp6 +
					       sizeof(struct icmp6_hdr));

		/* Remove BC entry if present */
		bcp = mip6_bc_find(&ip6_icmp->ip6_dst);
		if (bcp && !bcp->hr_flag)
			mip6_bc_delete(bcp, &bcp_nxt);
		break;

	case ICMP6_PARAM_PROB:
		if (icmp6->icmp6_code != ICMP6_PARAMPROB_OPTION)
			break;

		/* First we have to find the destination address
		   from the original IPv6 packet. Make sure that
		   the ptr is within the ICMPv6 packet. */
		err_off = ntohl(icmp6->icmp6_data32[0]);
		if ((off + sizeof(struct icmp6_hdr) + err_off) >=
		    m->m_pkthdr.len)
			return 0;

		ip6_icmp = (struct ip6_hdr *)((caddr_t)icmp6 +
					      sizeof(struct icmp6_hdr));

		/* Check which option that failed */
		err_ptr = (u_int8_t *) ((caddr_t)icmp6 +
					sizeof(struct icmp6_hdr) +
					err_off);

		if (MIP6_IS_MN_ACTIVE && (*err_ptr == IP6OPT_BINDING_UPDATE)) {
			if (mip6_stop_bu_hook)
				(*mip6_stop_bu_hook)(&ip6_icmp->ip6_dst);
		}

		if (*err_ptr == IP6OPT_HOME_ADDRESS) {
			log(LOG_ERR,
			    "Node %s does not recognize Home Address option\n",
			    ip6_sprintf(&ip6_icmp->ip6_dst));
			/* The message is discarded by the icmp code. */
		}
		break;

	case ND_ROUTER_ADVERT:
		if (icmp6->icmp6_code != 0)
			break;
		if (icmp6len < sizeof(struct nd_router_advert))
			break;

		ra = (struct nd_router_advert *)icmp6;
		if ((ra->nd_ra_flags_reserved & ND_RA_FLAG_HA) == 0)
			break;

		if (mip6_rec_ra_hook) {
			res = mip6_rec_ra_hook(m, off);
			if (res) return res;
			break;
		}
	}
	return 0;
}



/*
 ##############################################################################
 #
 # CONTROL SIGNAL FUNCTIONS
 # Functions for processing of incoming control signals (Binding Update and
 # Home Address option).
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_rec_bu
 * Description: Receive a Binding Update option and evaluate the contents.
 * Ret value:   0             Everything is OK.
 *              IPPROTO_DONE  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_rec_bu(m_in, off)
struct mbuf *m_in;  /* Mbuf containing the entire IPv6 packet */
int          off;   /* Offset from start of mbuf to start of dest option */
{
	struct in6_addr        *src_addr;   /* Src addr for HA sending BU */
	struct mip6_subopt_hal *hal;        /* Home Agents List sub-option */
	struct mip6_bc         *bcp;        /* Binding Cache list entry */
	struct mip6_bc         *bcp_nxt;
	struct in6_addr        *coa;        /* COA of the MN sending the BU */
	struct mip6_subbuf     *subbuf;     /* Buffer containing sub-options */
	struct in6_addr         ll_allnode; /* Link local all nodes address */
	u_int32_t   min_time;     /* Minimum lifetime to be sent in BA */
	u_long      na_flags = 0; /* Flags for NA message */
	int         send_na;      /* If node becomes HA for MN, broadcast NA */
	int         res, error;
	u_int8_t    rtr;
#if MIP6_DEBUG
	u_int8_t    var;
	int         offset, ii;
#endif

	subbuf = NULL;

	/* Find the care-of address used by the MN when sending the BU. */
	if (mip6_inp->coa)
		coa = &mip6_inp->coa->coa;
	else
		coa = &mip6_inp->ip6_src;

	/* Make sure that the BU contains a valid AH or ESP header. */
#if IPSEC
#ifndef __OpenBSD__
	if ( !((m_in->m_flags & M_AUTHIPHDR && m_in->m_flags & M_AUTHIPDGM) ||
	       (m_in->m_flags & M_AUTHIPDGM && m_in->m_flags & M_DECRYPTED))) {
		ip6stat.ip6s_badoptions++;
		log(LOG_INFO,
		    "%s: No AH or ESP header in BU from host %s\n",
		    __FUNCTION__,
		    ip6_sprintf(coa));
		return IPPROTO_DONE;
	}
#endif
#endif

	/* Make sure that the BU contains a valid Home Address option. */
	if ((mip6_inp->optflag & MIP6_DSTOPT_HA) == 0) {
		ip6stat.ip6s_badoptions++;
		log(LOG_INFO,
		    "%s: No Home Address option included in BU from host %s\n",
		    __FUNCTION__, ip6_sprintf(coa));
		return IPPROTO_DONE;
	}

	/* Make sure that the length field in the BU is >= 8. */
	if (mip6_inp->bu_opt->len < IP6OPT_BULEN) {
		ip6stat.ip6s_badoptions++;
		log(LOG_INFO,
		    "%s: Length field to short (%d) in BU from host %s\n",
		    __FUNCTION__, mip6_inp->bu_opt->len, ip6_sprintf(coa));
		return IPPROTO_DONE;
	}

	/* The sequence no in the BU must be greater than or equal to the
	   sequence number in the previous BU recieved (modulo 2^^16). */
	send_na = 0;
	bcp = mip6_bc_find(&mip6_inp->ha_opt->home_addr);
	if (bcp != NULL) {
		if (MIP6_LEQ(mip6_inp->bu_opt->seqno, bcp->seqno)) {
			ip6stat.ip6s_badoptions++;
			log(LOG_INFO,
			    "%s: Received sequence number (%d) <= "
			    "current (%d) in BU from host %s\n",
			    __FUNCTION__, mip6_inp->bu_opt->seqno,
			    bcp->seqno, ip6_sprintf(coa));
			return IPPROTO_DONE;
		}
		if (!bcp->hr_flag)
			send_na = 1;
	} else
		send_na = 1;

#if MIP6_DEBUG
	mip6_debug("\nReceived Binding Update\n");
	mip6_debug("IP Header Src:     %s\n",
		   ip6_sprintf(&mip6_inp->ip6_src));
	mip6_debug("IP Header Dst:     %s\n",
		   ip6_sprintf(&mip6_inp->ip6_dst));
	mip6_debug("Type/Length/Flags: %x / %u / ",
		   mip6_inp->bu_opt->type, mip6_inp->bu_opt->len);
	if (mip6_inp->bu_opt->flags & MIP6_BU_AFLAG)
		mip6_debug("A ");
	if (mip6_inp->bu_opt->flags & MIP6_BU_HFLAG)
		mip6_debug("H ");
	if (mip6_inp->bu_opt->flags & MIP6_BU_RFLAG)
		mip6_debug("R ");
	mip6_debug("\n");
	mip6_debug("Seq no/Life time:  %u / %u\n",
		   mip6_inp->bu_opt->seqno,
		   mip6_inp->bu_opt->lifetime);
	mip6_debug("Prefix length:     %u\n",
		   mip6_inp->bu_opt->prefix_len);

	if (mip6_inp->bu_opt->len > IP6OPT_BULEN) {
		offset = mip6_opt_offset(m_in, off, IP6OPT_BINDING_UPDATE);
		if (offset == 0) goto end_debug;

		mip6_debug("Sub-options present (TLV coded)\n");
		for (ii = IP6OPT_BULEN; ii < mip6_inp->bu_opt->len; ii++) {
			if ((ii - IP6OPT_BULEN) % 16 == 0)
				mip6_debug("\t0x:");
			if ((ii - IP6OPT_BULEN) % 4 == 0)
				mip6_debug(" ");
			m_copydata(m_in, offset + 2 + ii, sizeof(var),
				   (caddr_t)&var);
			mip6_debug("%02x", var);
			if ((ii - IP6OPT_BULEN + 1) % 16 == 0)
				mip6_debug("\n");
		}
		if ((ii - IP6OPT_BULEN) % 16)
			mip6_debug("\n");
	}
  end_debug:
#endif

	/* Shall Dynamic Home Agent Address Discovery be performed? */
	src_addr = NULL;
	hal = NULL;

	if (MIP6_IS_HA_ACTIVE) {
		if ((mip6_inp->ip6_dst.s6_addr8[15] & 0x7f) ==
		    MIP6_ADDR_ANYCAST_HA) {
			if (mip6_global_addr_hook)
				src_addr = (*mip6_global_addr_hook)
					(&mip6_inp->ip6_dst);
			if (src_addr == NULL) {
				log(LOG_ERR,
				    "%s: No global source address found\n",
				    __FUNCTION__);
				return IPPROTO_DONE;
			}

			if (mip6_hal_dynamic_hook)
				hal = (*mip6_hal_dynamic_hook)(src_addr);
			if (mip6_store_subopt(&subbuf, (caddr_t)hal)) {
				if (subbuf) _FREE(subbuf, M_TEMP);
				return IPPROTO_DONE;
			}
			error = mip6_send_ba(src_addr,
					     &mip6_inp->ha_opt->home_addr,
					     coa, subbuf, MIP6_BA_STATUS_DHAAD,
					     mip6_inp->bu_opt->seqno, 0);
			return error;
		}
	}

	/* Check if BU includes Unique Identifier sub-option is present. */
	/* XXX Code have to be added. */

	/* Check if this is a request to cache a binding for the MN. */
	if ((mip6_inp->bu_opt->lifetime != 0) &&
	    (! IN6_ARE_ADDR_EQUAL(&mip6_inp->ha_opt->home_addr, coa))) {
		/* The request to cache the binding depends on if the H-bit
		   is set or not in the BU. */
		error = 0;
		if (mip6_inp->bu_opt->flags & MIP6_BU_HFLAG) {
			/* The H-bit is set. Register the primary coa. Is the
			   node is a router implementing HA functionality */
			if ((!ip6_forwarding || !MIP6_IS_HA_ACTIVE) &&
			    (mip6_inp->bu_opt->flags & MIP6_BU_AFLAG)) {
				error = mip6_send_ba(
					&mip6_inp->ip6_dst,
					&mip6_inp->ha_opt->home_addr,
					coa, NULL, MIP6_BA_STATUS_HOMEREGNOSUP,
					mip6_inp->bu_opt->seqno, 0);
				return error;
			}

			/* Verify that the home address is an on-link IPv6
			   address and that the prefix length is correct. */
			res = mip6_addr_on_link(&mip6_inp->ha_opt->home_addr,
						mip6_inp->bu_opt->prefix_len);
			if ((res != 0) &&
			    (mip6_inp->bu_opt->flags & MIP6_BU_AFLAG)) {
				error = mip6_send_ba(
					&mip6_inp->ip6_dst,
					&mip6_inp->ha_opt->home_addr,
					coa, NULL, res,
					mip6_inp->bu_opt->seqno, 0);
				return error;
			}

			/* Other reject reasons may be added, e.g.
			   insufficient resources to serve a MN. */
			/* XXX Code may be added. */

			/* The BU is OK and this node becomes the HA for
			   the MN. Find out which lifetime to use in the BA */
			min_time = mip6_min_lifetime(
				&mip6_inp->ha_opt->home_addr,
				mip6_inp->bu_opt->prefix_len);
			min_time = min(min_time,
				       mip6_inp->bu_opt->lifetime);

			/* Create a new or update an existing BC entry. */
			rtr = mip6_inp->bu_opt->flags & MIP6_BU_RFLAG;
			bcp = mip6_bc_find(&mip6_inp->ha_opt->home_addr);
			if (bcp)
				mip6_bc_update(bcp, coa, min_time, 1, rtr,
					       mip6_inp->bu_opt->prefix_len,
					       mip6_inp->bu_opt->seqno,
					       bcp->info, bcp->lasttime);
			else {
				bcp = mip6_bc_create(
					&mip6_inp->ha_opt->home_addr,
					coa, min_time, 1, rtr,
					mip6_inp->bu_opt->prefix_len,
					mip6_inp->bu_opt->seqno);
				if (bcp == NULL)
					return IPPROTO_DONE;
			}

			/* Send a BA to the mobile node if the A-bit is
			   set in the BU. */
			if (mip6_inp->bu_opt->flags & MIP6_BU_AFLAG) {
				error = mip6_send_ba(&mip6_inp->ip6_dst,
						     &bcp->home_addr,
						     &bcp->coa,
						     NULL,
						     MIP6_BA_STATUS_ACCEPT,
						     bcp->seqno,
						     bcp->lifetime);
				if (error)
					return error;
			}

			/* The HA shall act as a proxy for the MN while it
			   is at a FN. Create a new or move an existing
			   tunnel to the MN. */
			error = mip6_tunnel(&mip6_inp->ip6_dst,
					    &bcp->coa,
					    MIP6_TUNNEL_MOVE, MIP6_NODE_HA,
					    (void *)bcp);
			if (error)
				return IPPROTO_DONE;
			error = mip6_proxy(&bcp->home_addr,
					   &mip6_inp->ip6_dst, RTM_ADD);
			if (error) {
#if MIP6_DEBUG
				mip6_debug("%s: set proxy error = %d\n",
					   __FUNCTION__, error);
#endif
				return IPPROTO_DONE;
			}

			/* Create a NA for the MN if the HA did not already
			   have a BC entry for this MN marked as a "home
			   registration".
			   The first NA will be sent in the create function,
			   the remaining NAs are sent by the timer function. */
			if (send_na) {
				ll_allnode = in6addr_linklocal_allnodes;
				na_flags |= ND_NA_FLAG_OVERRIDE;
				if (mip6_inp->bu_opt->flags & MIP6_BU_RFLAG)
					na_flags |= ND_NA_FLAG_ROUTER;

				mip6_na_create(&mip6_inp->ha_opt->home_addr,
					       &ll_allnode,
					       &mip6_inp->ha_opt->home_addr,
					       mip6_inp->bu_opt->prefix_len,
					       na_flags, 1);
			}
		} else {
			/* The H-bit is NOT set. Request to cache a binding.
			   Create a new or update an existing BC entry. */
			rtr = mip6_inp->bu_opt->flags & MIP6_BU_RFLAG;
			bcp = mip6_bc_find(&mip6_inp->ha_opt->home_addr);
			if (bcp)
				mip6_bc_update(bcp, coa,
					       mip6_inp->bu_opt->lifetime,
					       0, rtr,
					       mip6_inp->bu_opt->prefix_len,
					       mip6_inp->bu_opt->seqno,
					       bcp->info, bcp->lasttime);
			else {
				bcp = mip6_bc_create(
					&mip6_inp->ha_opt->home_addr,
					coa, mip6_inp->bu_opt->lifetime,
					0, rtr, mip6_inp->bu_opt->prefix_len,
					mip6_inp->bu_opt->seqno);
				if (bcp == NULL)
					return IPPROTO_DONE;
			}

			/* Send a BA to the mobile node if the A-bit is
			   set in the BU. */
			if (mip6_inp->bu_opt->flags & MIP6_BU_AFLAG) {
				error = mip6_send_ba(&mip6_inp->ip6_dst,
						     &bcp->home_addr,
						     &bcp->coa, NULL,
						     MIP6_BA_STATUS_ACCEPT,
						     bcp->seqno,
						     bcp->lifetime);
				return error;
			}
		}
		return 0;
	}

	/* Check if this is a request to delete a binding for the MN. */
	if ((mip6_inp->bu_opt->lifetime == 0) ||
	    (IN6_ARE_ADDR_EQUAL(&mip6_inp->ha_opt->home_addr, coa))) {
		/* The request to delete the binding depends on if the
		   H-bit is set or not in the BU. */
		if (mip6_inp->bu_opt->flags & MIP6_BU_HFLAG) {
			/* The H-bit is set. Make sure that there is an
			   entry in the BC marked as "home registration"
			   for this MN. */
			error = 0;
			if (((bcp == NULL) || (bcp->hr_flag == 0)) &&
			    (mip6_inp->bu_opt->flags & MIP6_BU_AFLAG)) {
				error = mip6_send_ba(
					&mip6_inp->ip6_dst,
					&mip6_inp->ha_opt->home_addr,
					coa, NULL, MIP6_BA_STATUS_NOTHA,
					mip6_inp->bu_opt->seqno, 0);
				return error;
			}

			/* The HA should delete BC entry, remove tunnel and
			   stop acting as a proxy for the MN. */
			error = mip6_bc_delete(bcp, &bcp_nxt);
			if (error)
				return IPPROTO_DONE;

			/* Send a BA to the MN if the A-bit is set. */
			if (mip6_inp->bu_opt->flags & MIP6_BU_AFLAG) {
				error = mip6_send_ba(
					&mip6_inp->ip6_dst,
					&mip6_inp->ha_opt->home_addr,
					coa, NULL, MIP6_BA_STATUS_ACCEPT,
					mip6_inp->bu_opt->seqno, 0);
				if (error)
					return error;
			}
		} else {
			/* The H-bit is NOT set. Request the CN to delete
			   the binding. */
			if (bcp != NULL) {
				error = mip6_bc_delete(bcp, &bcp_nxt);
				if (error)
					return IPPROTO_DONE;
			}

			if (mip6_inp->bu_opt->flags & MIP6_BU_AFLAG) {
				error = mip6_send_ba(
					&mip6_inp->ip6_dst,
					&mip6_inp->ha_opt->home_addr,
					coa, NULL, MIP6_BA_STATUS_ACCEPT,
					mip6_inp->bu_opt->seqno, 0);
				if (error)
					return error;
			}
		}
		return 0;
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_ha2srcaddr
 * Description: Copy Home Address option to IPv6 header source address, i.e
 *              replacing the existing source address.
 ******************************************************************************
 */
void
mip6_ha2srcaddr(m)
struct mbuf  *m;  /* The entire IPv6 packet */
{
	register struct ip6_hdr  *ip6;  /* IPv6 header */

#if MIP6_DEBUG
	mip6_debug("\nReceived Home Address Option\n");
	mip6_debug("Type/Length:  %x / %u\n", mip6_inp->ha_opt->type,
		   mip6_inp->ha_opt->len);
	mip6_debug("Home Address: %s\n",
		   ip6_sprintf(&mip6_inp->ha_opt->home_addr));
#endif

	/* Copy the Home Address option address to the Source Address */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_src = mip6_inp->ha_opt->home_addr;
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
 * Function:    mip6_send_ba
 * Description: Send a Binding Acknowledgement back to the Mobile Node. A new
 *              IPv6 packet is built including a IPv6 header, a Routing header
 *              and a Destination header (where the BA is stored).
 * Ret value:   0 OK
 *              IPPROTO_DONE If anything goes wrong.
 ******************************************************************************
 */
int
mip6_send_ba(ip6_src, ip6_dst, coa, subbuf, status, seqno, lifetime)
struct in6_addr     *ip6_src;  /* Source address for packet */
struct in6_addr     *ip6_dst;  /* Destination address for packet */
struct in6_addr     *coa;      /* Care-of address for MN */
struct mip6_subbuf  *subbuf;   /* Home Agents List sub-option */
u_int8_t             status;   /* Result of the Binding Update request */
u_int16_t            seqno;    /* Seq no in the BU being acknowledged */
u_int32_t            lifetime; /* Proposed lifetime in the BU */
{
	struct mbuf         *m_ip6;   /* IPv6 header stored in a mbuf */
	struct mip6_opt_ba  *ba_opt;  /* BA allocated in this function */
	struct ip6_pktopts  *opt;     /* Options for IPv6 packet */
	int                  error;
#if MIP6_DEBUG
	u_int8_t             var;
	int                  ii;
#endif

	opt = (struct ip6_pktopts *)MALLOC ip6_pktopts),
					   M_TEMP, M_WAITOK);
	if (opt == NULL)
		return IPPROTO_DONE;
	bzero(opt, sizeof(struct ip6_pktopts));

	opt->ip6po_hlim = -1;       /* -1 means to use default hop limit */
	m_ip6 = mip6_create_ip6hdr(ip6_src, ip6_dst, IPPROTO_NONE);
	if(m_ip6 == NULL)
		return IPPROTO_DONE;

	opt->ip6po_rhinfo.ip6po_rhi_rthdr = mip6_create_rh(coa,
							   IPPROTO_DSTOPTS);
	if(opt->ip6po_rhinfo.ip6po_rhi_rthdr == NULL)
		return IPPROTO_DONE;

	ba_opt = mip6_create_ba(status, seqno, lifetime);
	if (ba_opt == NULL)
		return IPPROTO_DONE;

	opt->ip6po_dest2 = mip6_create_dh((void *)ba_opt, subbuf,
					  IPPROTO_NONE);
	if(opt->ip6po_dest2 == NULL)
		return IPPROTO_DONE;

	mip6_config.enable_outq = 0;
	error = ip6_output(m_ip6, opt, NULL, 0, NULL, NULL);
	if (error) {
		_FREE(opt->ip6po_rhinfo.ip6po_rhi_rthdr, M_TEMP);
		_FREE(opt->ip6po_dest2, M_TEMP);
		_FREE(ba_opt, M_TEMP);
		mip6_config.enable_outq = 1;
		log(LOG_ERR,
		    "%s: ip6_output function failed to send BA, error = %d\n",
		    __FUNCTION__, error);
		return error;
	}
	mip6_config.enable_outq = 1;

#if MIP6_DEBUG
	mip6_debug("\nSent Binding Acknowledgement\n");
	mip6_debug("IP Header Src:      %s\n", ip6_sprintf(ip6_src));
	mip6_debug("IP Header Dst:      %s\n", ip6_sprintf(ip6_dst));
	mip6_debug("Type/Length/Status: %x / %u / %u\n",
		   ba_opt->type, ba_opt->len, ba_opt->status);
	mip6_debug("Seq no/Life time:   %u / %u\n",
		   ba_opt->seqno, ba_opt->lifetime);
	mip6_debug("Refresh time:       %u\n", ba_opt->refresh);

	if (subbuf) {
		mip6_debug("Sub-options present (TLV coded)\n");
		for (ii = 0; ii < subbuf->len; ii++) {
			if (ii % 16 == 0)
				mip6_debug("\t0x:");
			if (ii % 4 == 0)
				mip6_debug(" ");
			bcopy((caddr_t)&subbuf->buffer[ii], (caddr_t)&var, 1);
			mip6_debug("%02x", var);
			if ((ii + 1) % 16 == 0)
				mip6_debug("\n");
		}
		if (ii % 16)
			mip6_debug("\n");
	}
#endif

	_FREE(opt->ip6po_rhinfo.ip6po_rhi_rthdr, M_TEMP);
	_FREE(opt->ip6po_dest2, M_TEMP);
	_FREE(ba_opt, M_TEMP);
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_send_na
 * Description: Sends a Neighbor Advertisement for a specific prefix. If the
 *              address is a aggregatable unicast address, i.e. prefix length
 *              is 64, a NA is sent to the site local and link local addresse
 *              as well.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_send_na(nap)
struct mip6_na    *nap;         /* Neighbor Advertisement sent */
{
	struct mip6_prefix   *pq;
	struct nd_prefix     *pr;         /* Prefix list entry */
	struct in6_addr       new_addr;   /* New constructed address */
	struct in6_addr       sl_addr;    /* Site local address */

	nap->no -= 1;

#if MIP6_DEBUG
	mip6_debug("\nSent Neighbor Advertisement (0x%x)\n", nap);
#endif

	/* Send NA for specified address if length equal to 0, otherwise for
	   each prefix with the same length as the address.
	   Different prefix list is used for HA and MN. */
	if (nap->prefix_len == 0) {
		nd6_na_output(nap->ifp, &nap->dst_addr, &nap->target_addr,
			      nap->flags, nap->use_link_opt, NULL);
#if MIP6_DEBUG
		mip6_debug("Target Address: %s\n",
			   ip6_sprintf(&nap->target_addr));
#endif
	}

	if ((MIP6_IS_HA_ACTIVE) && (nap->prefix_len != 0)) {
		for (pq = mip6_pq; pq; pq = pq->next) {
			if ((nap->prefix_len == pq->prefix_len) &&
			    in6_are_prefix_equal(&pq->prefix,
						 &nap->target_addr,
						 pq->prefix_len)) {
				mip6_build_in6addr(&new_addr,
						   &nap->target_addr,
						   &pq->prefix,
						   pq->prefix_len);
				nd6_na_output(nap->ifp, &nap->dst_addr,
					      &new_addr, nap->flags,
					      nap->use_link_opt, NULL);
#if MIP6_DEBUG
				mip6_debug("Target Address: %s\n",
					   ip6_sprintf(&new_addr));
#endif
			} else
				continue;

			if (nap->prefix_len == 64) {
				/* NA for the site-local address is
				   only sent if length equals to 64. */
				bcopy((caddr_t)&in6addr_sitelocal,
				      (caddr_t)&sl_addr, 6);
				bcopy((caddr_t)&nap->target_addr + 6,
				      (caddr_t)&sl_addr + 6, 2);
				mip6_build_in6addr(&new_addr,
						   &nap->target_addr,
						   &sl_addr,
						   nap->prefix_len);
				nd6_na_output(nap->ifp,
					      &nap->dst_addr,
					      &new_addr,
					      nap->flags,
					      nap->use_link_opt, NULL);
#if MIP6_DEBUG
				mip6_debug("Target Address: %s\n",
					   ip6_sprintf(&new_addr));
#endif

				/* NA for the link-local address is
				   only sent if length equals to 64. */
				mip6_build_in6addr(&new_addr,
						   &nap->target_addr,
						   &in6addr_linklocal,
						   nap->prefix_len);
				nd6_na_output(nap->ifp,
					      &nap->dst_addr,
					      &new_addr,
					      nap->flags,
					      nap->use_link_opt, NULL);
#if MIP6_DEBUG
				mip6_debug("Target Address: %s\n",
					   ip6_sprintf(&new_addr));
#endif
			}
		}
	} else {
		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
			if ((nap->prefix_len == pr->ndpr_plen) &&
			    in6_are_prefix_equal(&nap->target_addr,
						 &pr->ndpr_addr,
						 pr->ndpr_plen)) {
				mip6_build_in6addr(
					&new_addr,
					&nap->target_addr,
					&pr->ndpr_prefix.sin6_addr,
					pr->ndpr_plen);
				nd6_na_output(nap->ifp,
					      &nap->dst_addr,
					      &new_addr,
					      nap->flags,
					      nap->use_link_opt, NULL);
#if MIP6_DEBUG
				mip6_debug("Target Address: %s\n",
					   ip6_sprintf(&new_addr));
#endif
			} else
				continue;

			if (nap->prefix_len == 64) {
				/* NA for the site-local address is
				   only sent if length equals to 64. */
				bcopy((caddr_t)&in6addr_sitelocal,
				      (caddr_t)&sl_addr, 6);
				bcopy((caddr_t)&nap->target_addr + 6,
				      (caddr_t)&sl_addr + 6, 2);
				mip6_build_in6addr(&new_addr,
						   &nap->target_addr,
						   &sl_addr,
						   nap->prefix_len);
				nd6_na_output(nap->ifp,
					      &nap->dst_addr,
					      &new_addr,
					      nap->flags,
					      nap->use_link_opt, NULL);
#if MIP6_DEBUG
				mip6_debug("Target Address: %s\n",
					   ip6_sprintf(&new_addr));
#endif

				/* NA for the link-local address is
				   only sent if length equals to 64. */
				mip6_build_in6addr(&new_addr,
						   &nap->target_addr,
						   &in6addr_linklocal,
						   nap->prefix_len);
				nd6_na_output(nap->ifp,
					      &nap->dst_addr,
					      &new_addr,
					      nap->flags,
					      nap->use_link_opt, NULL);
#if MIP6_DEBUG
				mip6_debug("Target Address: %s\n",
					   ip6_sprintf(&new_addr));
#endif
			}
		}
	}
	return;
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
 * Function:    mip6_create_ip6hdr
 * Description: Create and fill in data for an IPv6 header to be used by
 *              packets originating from MIPv6.
 * Ret value:   NULL if a IPv6 header could not be created.
 *              Otherwise, pointer to a mbuf including the IPv6 header.
 ******************************************************************************
 */
struct mbuf *
mip6_create_ip6hdr(ip6_src, ip6_dst, next)
struct in6_addr *ip6_src;  /* Source address for packet */
struct in6_addr *ip6_dst;  /* Destination address for packet */
u_int8_t        next;      /* Next header following the IPv6 header */
{
	struct ip6_hdr  *ip6;  /* IPv6 header */
	struct mbuf     *m;    /* Ptr to mbuf allocated for output data */

	/* Allocate memory for the IPv6 header and fill it with data */
	ip6 = (struct ip6_hdr *)MALLOC ip6_hdr),
				       M_TEMP, M_WAITOK);
	if (ip6 == NULL)
		return NULL;
	bzero(ip6, sizeof(struct ip6_hdr));

	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_plen = 0;
	ip6->ip6_nxt = next;
	ip6->ip6_hlim = IPV6_DEFHLIM;

	ip6->ip6_src = *ip6_src;
	ip6->ip6_dst = *ip6_dst;

	/* Allocate memory for mbuf and copy IPv6 header to mbuf. */
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL) {
		return NULL;
	}

	m->m_len = sizeof(*ip6);
	m->m_pkthdr.len = m->m_len;
	m->m_pkthdr.rcvif = NULL;
	bcopy((caddr_t)ip6, mtod(m, caddr_t), sizeof(*ip6));
	_FREE(ip6, M_TEMP);
	return m;
}



/*
 ******************************************************************************
 * Function:    mip6_create_rh
 * Description: Create a routing header of type 0 and add the COA for the MN.
 * Ret value:   A pointer to the ip6_rthdr structure if everything is OK.
 *              Otherwise NULL.
 ******************************************************************************
 */
struct ip6_rthdr *
mip6_create_rh(coa, next)
struct in6_addr  *coa;  /* Care-of address for the MN */
u_int8_t         next;  /* Next header following the routing header */
{
	struct ip6_rthdr0  *rthdr0;  /* Routing header type 0 */
	int                 len;

	len = sizeof(struct ip6_rthdr0) + sizeof(struct in6_addr);
	rthdr0 = (struct ip6_rthdr0 *)MALLOC M_TEMP, M_WAITOK);
	if (rthdr0 == NULL)
		return NULL;
	bzero(rthdr0, len);

	rthdr0->ip6r0_nxt = next;
	rthdr0->ip6r0_len = 2;
	rthdr0->ip6r0_type = 0;
	rthdr0->ip6r0_segleft = 1;
	rthdr0->ip6r0_reserved = 0;
	bcopy((caddr_t)coa, (caddr_t)rthdr0 + sizeof(struct ip6_rthdr0),
	      sizeof(struct in6_addr));
	return (struct ip6_rthdr *)rthdr0;
}



/*
 ******************************************************************************
 * Function:    mip6_create_ba
 * Description: Create a Binding Acknowledgement option for transmission.
 * Ret value:   NULL if a BA option could not be created.
 *              Otherwise, pointer to the BA option.
 ******************************************************************************
 */
struct mip6_opt_ba *
mip6_create_ba(status, seqno, lifetime)
u_int8_t   status;    /* Result of the Binding Update request */
u_int16_t  seqno;     /* Sequence number in the BU being acknowledged */
u_int32_t  lifetime;  /* Proposed lifetime in the BU */
{
	struct mip6_opt_ba  *ba_opt;  /* BA allocated in this function */

	/* Allocate a Binding Aknowledgement option and set values */
	ba_opt = (struct mip6_opt_ba *)MALLOC mip6_opt_ba),
					      M_TEMP, M_WAITOK);
	if (ba_opt == NULL)
		return NULL;
	bzero(ba_opt, sizeof(struct mip6_opt_ba));

	ba_opt->type = IP6OPT_BINDING_ACK;
	ba_opt->len = IP6OPT_BALEN;
	ba_opt->status = status;
	ba_opt->seqno = seqno;
	ba_opt->lifetime = lifetime;

	/* Calculate value for refresh time */
	if (MIP6_IS_HA_ACTIVE)
		ba_opt->refresh = (ba_opt->lifetime * 8) / 10;
	else
		ba_opt->refresh = ba_opt->lifetime;

	return ba_opt;
}



/*
 ******************************************************************************
 * Function:    mip6_create_dh
 * Description: Create a destination header and add either a BA or BU option.
 * Ret value:   A pointer to the ip6_dest structure if everything is OK.
 *              Otherwise NULL.
 ******************************************************************************
 */
struct ip6_dest *
mip6_create_dh(arg_opt, arg_sub, next)
void                *arg_opt;  /* BU or a BA option */
struct mip6_subbuf  *arg_sub;  /* BU or BA sub-option (NULL if not present) */
u_int8_t             next;      /* Next header following the dest header */
{
	struct mip6_opt *opt;   /* Destination option */
	struct ip6_dest *dest;  /* Destination header */
	int             off;    /* Offset from start of Dest Header (byte) */
	int             error;  /* Error code from function call */

	opt = (struct mip6_opt *)arg_opt;
	dest = NULL;
	if (opt->type == IP6OPT_BINDING_ACK) {
		off = 3;
		error = mip6_add_ba(&dest, &off,
				    (struct mip6_opt_ba *)opt, arg_sub);
		if (error) {
			if (dest != NULL)
				_FREE(dest, M_TEMP);
			return NULL;
		}
		dest->ip6d_nxt = next;
	} else if (opt->type == IP6OPT_BINDING_UPDATE) {
		off = 2;
		error = mip6_add_bu(&dest, &off,
				    (struct mip6_opt_bu *)opt, arg_sub);
		if (error) {
			if (dest != NULL)
				_FREE(dest, M_TEMP);
			return NULL;
		}
		dest->ip6d_nxt = next;
	}
	return dest;
}



/*
 ******************************************************************************
 * Function:    mip6_opt_offset
 * Description: Find offset for BU, BA or BR option in the Destination Header.
 *              The option type is specified as input parameter and the offset
 *              to start of the first option of the specified type is returned.
 * Ret value:   Offset (bytes) to specified option from beginning of m_in.
 *              If no option is found a length of 0 is returned indicating an
 *              error.
 ******************************************************************************
 */
int
mip6_opt_offset(m_in, off, type)
struct mbuf *m_in;  /* Mbuf containing the entire IPv6 packet */
int          off;   /* Offset from start of mbuf to start of dest option */
int          type;  /* Type of option to look for */
{
	int        ii;       /* Internal counter */
	u_int8_t   opttype;  /* Option type found in Destination Header*/
	u_int8_t   optlen;   /* Option length incl type and length */
	u_int32_t  len;      /* Length of Destination Header in bytes */
	u_int8_t   len8;     /* Length of Destination Header in bytes */
	u_int32_t  offset;   /* Offset to BU option from beginning of m_in */

	m_copydata(m_in, off + 1, sizeof(len8), (caddr_t)&len8);
	len = (len8 + 1) << 3;

	offset = 0;
	for (ii = 2; ii < len;) {
		m_copydata(m_in, off + ii, sizeof(opttype), (caddr_t)&opttype);
		if (opttype == type) {
			offset = off + ii;
			break;
		} else if (opttype == IP6OPT_PAD1) {
			ii += 1;
			continue;
		} else {
			ii += 1;
		}

		m_copydata(m_in, off + ii, sizeof(optlen), (caddr_t)&optlen);
		ii += 1 + optlen;
	}
	return offset;
}



/*
 ******************************************************************************
 * Function:    mip6_addr_on_link
 * Description: Check if an address is an on-link IPv6 address with respect to
 *              the home agent's current prefix list.
 * Ret value:   0   = OK
 *              133 = Not home subnet
 *              136 = Incorrect interface identifier length
 ******************************************************************************
 */
int
mip6_addr_on_link(addr, prefix_len)
struct in6_addr *addr;       /* IPv6 address to check */
int             prefix_len;  /* Prefix length for the address */
{
	struct mip6_prefix  *pr;   /* Pointer to entries in the prexix list */

	for (pr = mip6_pq; pr; pr = pr->next) {
		/* Check if the IPv6 prefixes are equal, i.e. of the same
		   IPv6 type of address. */
		/* If they are, verify that the prefix length is correct. */
		if (in6_are_prefix_equal(addr, &pr->prefix, pr->prefix_len)) {
			if (prefix_len == 0)
				return 0;

			if (pr->prefix_len == prefix_len)
				return 0;
			else
				return MIP6_BA_STATUS_IFLEN;
		}
	}
	return MIP6_BA_STATUS_SUBNET;
}



/*
 ******************************************************************************
 * Function:    mip6_min_lifetime
 * Description: Decide the remaining valid lifetime for a home address. If the
 *              prefix length is zero the lifetime is the lifetime of the
 *              prefix list entry for this prefix.
 *              If the prefix length is non-zero the lifetime is the minimum
 *              remaining valid lifetime for all subnet prefixes on the mobile
 *              node's home link.
 * Note:        This function is only used by the Home Agent.
 * Ret value:   Lifetime
 ******************************************************************************
 */
u_int32_t
mip6_min_lifetime(addr, prefix_len)
struct in6_addr *addr;       /* IPv6 address to check */
int             prefix_len;  /* Prefix length for the address */
{
	struct mip6_prefix  *pr;        /* Ptr to entries in the prexix list */
	u_int32_t            min_time;  /* Minimum life time */

	min_time = 0xffffffff;

	for (pr = mip6_pq; pr; pr = pr->next) {
		/* Different handling depending on the prefix length. */
		if (prefix_len == 0) {
			if (in6_are_prefix_equal(addr, &pr->prefix,
						 pr->prefix_len)) {
				return pr->valid_time;
			}
		} else
			min_time = min(min_time, pr->valid_time);
	}
	return min_time;
}



/*
 ******************************************************************************
 * Function:    mip6_build_in6addr
 * Description: Build an in6 address from a prefix and the interface id.
 *              The length of the different parts is decided by prefix_len.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_build_in6addr(new_addr, id, prefix, prefix_len)
struct in6_addr        *new_addr;  /* New address built in this function */
struct in6_addr        *id;        /* Interface id part of the address */
const struct in6_addr  *prefix;    /* Prefix part of the address */
int                    prefix_len; /* Prefix length (bits) */
{
	u_int8_t  byte_pr, byte_id;
	int       ii, jj;

	for (ii = 0; ii < prefix_len / 8; ii++)
		new_addr->s6_addr8[ii] = prefix->s6_addr8[ii];

	if (prefix_len % 8) {
		/* Add the last bits of the prefix to the common byte. */
		byte_pr = prefix->s6_addr8[ii];
		byte_pr = byte_pr >> (8 - (prefix_len % 8));
		byte_pr = byte_pr << (8 - (prefix_len % 8));

		/* Then, add the first bits of the interface id to the
		   common byte. */
		byte_id = id->s6_addr8[ii];
		byte_id = byte_id << (prefix_len % 8);
		byte_id = byte_id >> (prefix_len % 8);
		new_addr->s6_addr8[ii] = byte_pr | byte_id;
		ii += 1;
	}

	for (jj = ii; jj < 16; jj++)
		new_addr->s6_addr8[jj] = id->s6_addr8[jj];
}



/*
 ******************************************************************************
 * Function:    mip6_build_ha_anycast
 * Description: Build an mobile IPv6 Home-Agents anycast address from a prefix
 *              and the prefix length. The interface id is according to
 *              RFC2526.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_build_ha_anycast(new_addr, prefix, prefix_len)
struct in6_addr       *new_addr;   /* New address built in this function */
const struct in6_addr *prefix;     /* Prefix part of the address */
int                    prefix_len; /* Prefix length (bits) */
{
	struct in6_addr   addr;


	if (prefix->s6_addr8[0] == 0xff) {
		*new_addr = in6addr_any;
		return;
	}

	if (((prefix->s6_addr8[0] & 0xe0) != 0) && (prefix_len != 64)) {
		*new_addr = in6addr_any;
		return;
	}

	if (((prefix->s6_addr8[0] & 0xe0) != 0) && (prefix_len == 64))
		addr = in6addr_aha_64;
	else
		addr = in6addr_aha_nn;

	mip6_build_in6addr(new_addr, &addr, prefix, prefix_len);
}



/*
 ******************************************************************************
 * Function:    mip6_add_ifaddr
 * Description: Similar to "ifconfig <ifp> <addr> prefixlen <plen>".
 * Ret value:   Standard error codes.
 ******************************************************************************
 */
int
mip6_add_ifaddr(struct in6_addr *addr,
		struct ifnet *ifp,
		int plen,
		int flags) /* Note: IN6_IFF_NODAD available flag */
{
	struct in6_aliasreq    *ifra, dummy;
	struct sockaddr_in6    *sa6;
	struct sockaddr_in6     oldaddr;
	struct in6_ifaddr      *ia, *oia;
	struct in6_addrlifetime *lt;
	int	error = 0, hostIsNew, prefixIsNew;
	int	s;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	struct ifaddr *ifa;
#endif
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	time_t time_second = (time_t)time.tv_sec;
#endif

	bzero(&dummy, sizeof(dummy));
	ifra = &dummy;

	ifra->ifra_addr.sin6_len = sizeof(ifra->ifra_addr);
	ifra->ifra_addr.sin6_family = AF_INET6;
	ifra->ifra_addr.sin6_addr = *addr;

	if (plen != 0) {
		ifra->ifra_prefixmask.sin6_len =
			sizeof(ifra->ifra_prefixmask);
		ifra->ifra_prefixmask.sin6_family = AF_INET6;
		in6_prefixlen2mask(&ifra->ifra_prefixmask.sin6_addr, plen);
		/* XXXYYY Should the prefix also change its prefixmask? */
	}

	ifra->ifra_flags = flags;
	ifra->ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra->ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	sa6 = &ifra->ifra_addr;

	/* "ifconfig ifp inet6 Home_Address prefixlen 64/128 (alias?)" */
	if (ifp == 0)
		return EOPNOTSUPP;

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
 	ia = in6ifa_ifpwithaddr(ifp, &sa6->sin6_addr);

	if (ia == 0) {
		ia = (struct in6_ifaddr *)
			MALLOC M_IFADDR, M_WAITOK);
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

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
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

	/* sanity for overflow - beware unsigned */
	lt = &ifra->ifra_lifetime;
	if (lt->ia6t_vltime != ND6_INFINITE_LIFETIME
	    && lt->ia6t_vltime + time_second < time_second) {
		splx(s);
		return EINVAL;
	}
	if (lt->ia6t_pltime != ND6_INFINITE_LIFETIME
	    && lt->ia6t_pltime + time_second < time_second) {
		splx(s);
		return EINVAL;
	}
	prefixIsNew = 0;
	hostIsNew = 1;

	if (ifra->ifra_addr.sin6_len == 0) {
		ifra->ifra_addr = ia->ia_addr;
		hostIsNew = 0;
	} else if (IN6_ARE_ADDR_EQUAL(&ifra->ifra_addr.sin6_addr,
				      &ia->ia_addr.sin6_addr))
		hostIsNew = 0;

	if (ifra->ifra_prefixmask.sin6_len) {
		in6_ifscrub(ifp, ia);
		ia->ia_prefixmask = ifra->ifra_prefixmask;
		prefixIsNew = 1;
	}
	if ((ifp->if_flags & IFF_POINTOPOINT) &&
	    (ifra->ifra_dstaddr.sin6_family == AF_INET6)) {
		in6_ifscrub(ifp, ia);
		oldaddr = ia->ia_dstaddr;
		ia->ia_dstaddr = ifra->ifra_dstaddr;
		/* link-local index check: should be a separate function? */
		if (IN6_IS_ADDR_LINKLOCAL(&ia->ia_dstaddr.sin6_addr)) {
			if (ia->ia_dstaddr.sin6_addr.s6_addr16[1] == 0) {
				/*
				 * interface ID is not embedded by
				 * the user
				 */
				ia->ia_dstaddr.sin6_addr.s6_addr16[1]
					= htons(ifp->if_index);
			} else if (ia->ia_dstaddr.sin6_addr.s6_addr16[1] !=
				   htons(ifp->if_index)) {
				ia->ia_dstaddr = oldaddr;
				splx(s);
				return(EINVAL);	/* ifid is contradict */
			}
		}
		prefixIsNew = 1; /* We lie; but effect's the same */
	}
	if (ifra->ifra_addr.sin6_family == AF_INET6 &&
	    (hostIsNew || prefixIsNew))
		{
			error = in6_ifinit(ifp, ia, &ifra->ifra_addr, 0);
		}
	if (ifra->ifra_addr.sin6_family == AF_INET6
	    && hostIsNew && (ifp->if_flags & IFF_MULTICAST)) {
		int error_local = 0;

		/*
		 * join solicited multicast addr for new host id
		 */
		struct in6_addr llsol;
		bzero(&llsol, sizeof(struct in6_addr));
		llsol.s6_addr16[0] = htons(0xff02);
		llsol.s6_addr16[1] = htons(ifp->if_index);
		llsol.s6_addr32[1] = 0;
		llsol.s6_addr32[2] = htonl(1);
		llsol.s6_addr32[3] =
			ifra->ifra_addr.sin6_addr.s6_addr32[3];
		llsol.s6_addr8[12] = 0xff;
		(void)in6_addmulti(&llsol, ifp, &error_local);
		if (error == 0)
			error = error_local;
	}

	ia->ia6_flags = ifra->ifra_flags;
	ia->ia6_flags &= ~IN6_IFF_DUPLICATED;	/*safety*/
	ia->ia6_flags &= ~IN6_IFF_NODAD;	/* Mobile IPv6 */

	ia->ia6_lifetime = ifra->ifra_lifetime;
	/* for sanity */
	if (ia->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME) {
		ia->ia6_lifetime.ia6t_expire =
			time_second + ia->ia6_lifetime.ia6t_vltime;
	} else
		ia->ia6_lifetime.ia6t_expire = 0;
	if (ia->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME) {
		ia->ia6_lifetime.ia6t_preferred =
			time_second + ia->ia6_lifetime.ia6t_pltime;
	} else
		ia->ia6_lifetime.ia6t_preferred = 0;

	/*
	 * Perform DAD, if needed.
	 * XXX It may be of use, if we can administratively
	 * disable DAD.
	 */
	switch (ifp->if_type) {
	case IFT_ARCNET:
	case IFT_ETHER:
	case IFT_FDDI:
#if 0
	case IFT_ATM:
	case IFT_SLIP:
	case IFT_PPP:
#endif
		/* Mobile IPv6 modification */
		if ((ifra->ifra_flags & IN6_IFF_NODAD) == 0) {
			ia->ia6_flags |= IN6_IFF_TENTATIVE;
			nd6_dad_start((struct ifaddr *)ia, NULL);
		}
		break;
	case IFT_DUMMY:
	case IFT_FAITH:
	case IFT_GIF:
	case IFT_LOOP:
	default:
		break;
	}

	if (hostIsNew) {
		int iilen;
		int error_local = 0;

		iilen = (sizeof(ia->ia_prefixmask.sin6_addr) << 3) -
			in6_mask2len(&ia->ia_prefixmask.sin6_addr);
		error_local = in6_prefix_add_ifid(iilen, ia);
		if (error == 0)
			error = error_local;
	}

    splx(s);
    return error;


}



/*
 ******************************************************************************
 * Function:    mip6_tunnel_output
 * Description: Encapsulates packet in an outer header which is determined
 *		of the Binding Cache entry provided. Note that packet is
 *		(currently) not sent here, but should be sent by the caller.
 * Ret value:   != 0 if failure. It's up to the caller to free the mbuf chain.
 ******************************************************************************
 */
int
mip6_tunnel_output(mp, bc)
	struct mbuf **mp;
	struct mip6_bc *bc;
{
	struct sockaddr_in6 dst;
	const struct encaptab *ep = bc->ep;
	struct mbuf *m = *mp;
	struct sockaddr_in6 *sin6_src = (struct sockaddr_in6 *)&ep->src;
	struct sockaddr_in6 *sin6_dst = (struct sockaddr_in6 *)&ep->dst;
	struct ip6_hdr *ip6;
	u_int8_t itos;
	int len;

	bzero(&dst, sizeof(dst));
	dst.sin6_len = sizeof(struct sockaddr_in6);
	dst.sin6_family = AF_INET6;
	dst.sin6_addr = bc->coa;

	if (ep->af != AF_INET6 || ep->dst.ss_len != dst.sin6_len ||
	    bcmp(&ep->dst, &dst, dst.sin6_len) != 0 )
		return EFAULT;

	/* Recursion problems? */

	if (IN6_IS_ADDR_UNSPECIFIED(&sin6_src->sin6_addr)) {
		return EFAULT;
	}

	len = m->m_pkthdr.len;

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m)
			return ENOBUFS;
	}
	ip6 = mtod(m, struct ip6_hdr *);
	itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;


	/* prepend new IP header */
	M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip6_hdr))
		m = m_pullup(m, sizeof(struct ip6_hdr));
	if (m == NULL) {
#if MIP6_DEBUG
		printf("ENOBUFS in mip6_tunnel_output %d\n", __LINE__);
#endif
		return ENOBUFS;
	}

	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow	= 0;
	ip6->ip6_vfc	&= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc	|= IPV6_VERSION;
	ip6->ip6_plen	= htons((u_short)len);
	ip6->ip6_nxt	= IPPROTO_IPV6;
	ip6->ip6_hlim	= ip6_gif_hlim;   /* Same? */
	ip6->ip6_src	= sin6_src->sin6_addr;

	/* bidirectional configured tunnel mode */
	if (!IN6_IS_ADDR_UNSPECIFIED(&sin6_dst->sin6_addr))
		ip6->ip6_dst = sin6_dst->sin6_addr;
	else
		return ENETUNREACH;

	*mp = m;
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_tunnel_input
 * Description: similar to gif_input() and in6_gif_input().
 * Ret value:	standard error codes.
 ******************************************************************************
 */
int
mip6_tunnel_input(mp, offp, proto)
struct mbuf **mp;
int          *offp, proto;
{
	struct mbuf    *m = *mp;
	struct ip6_hdr *ip6;
	int             s, af = 0;
	u_int32_t       otos;

	ip6 = mtod(m, struct ip6_hdr *);
	otos = ip6->ip6_flow;
	m_adj(m, *offp);

	switch (proto) {
	case IPPROTO_IPV6:
	{
		struct ip6_hdr *ip6;
		af = AF_INET6;
		if (m->m_len < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return IPPROTO_DONE;
		}
		m->m_flags |= M_MIP6TUNNEL;	/* Tell MN that this packet
						   was tunnelled. */
		ip6 = mtod(m, struct ip6_hdr *);

		s = splimp();
		if (IF_QFULL(&ip6intrq)) {
			IF_DROP(&ip6intrq);	/* update statistics */
			m_freem(m);
			splx(s);
			return IPPROTO_DONE;
		}
		IF_ENQUEUE(&ip6intrq, m);
#if 0
		/* we don't need it as we tunnel IPv6 in IPv6 only. */
		schednetisr(NETISR_IPV6);
#endif
		splx(s);
		break;
	}
	default:
#if MIP6_DEBUG
		mip6_debug("%s: protocol %d not supported.\n", __FUNCTION__,
			   proto);
#endif
		m_freem(m);
		return IPPROTO_DONE;
	}

	return IPPROTO_DONE;
}



/*
 ******************************************************************************
 * Function:    mip6_tunnel
 * Description: Create, move or delete a tunnel from the Home Agent to the MN
 *              or from the Mobile Node to the Home Agent.
 * Ret value:   Standard error codes.
 ******************************************************************************
 */
int
mip6_tunnel(ip6_src, ip6_dst, action, start, entry)
struct in6_addr  *ip6_src;   /* Tunnel start point */
struct in6_addr  *ip6_dst;   /* Tunnel end point */
int               action;    /* Action: MIP6_TUNNEL_{ADD,MOVE,DEL} */
int               start;     /* Either the Home Agent or the Mobile Node */
void             *entry;     /* BC or ESM depending on start variable */
{
	const struct encaptab *ep;	  /* Encapsulation entry */
	const struct encaptab **ep_store; /* Where to store encap reference */
	struct sockaddr_in6   src, srcm;
	struct sockaddr_in6   dst, dstm;
	struct in6_addr       mask;
	int                   mask_len = 128;

	ep_store = NULL;
	if ((start == MIP6_NODE_MN) && (entry != NULL))
		ep_store = &((struct mip6_esm *)entry)->ep;
	else if ((start == MIP6_NODE_HA) && (entry != NULL))
		ep_store = &((struct mip6_bc *)entry)->ep;
	else {
#if MIP6_DEBUG
		printf("%s: Tunnel not modified\n", __FUNCTION__);
#endif
		return 0;
	}

	if (action == MIP6_TUNNEL_DEL) {
		/* Moving to Home network. Remove tunnel. */
		if (ep_store && *ep_store) {
			encap_detach(*ep_store);
			*ep_store = NULL;
		}
		return 0;
	}

	if ((action == MIP6_TUNNEL_ADD) || (action == MIP6_TUNNEL_MOVE)) {
		if (action == MIP6_TUNNEL_MOVE && ep_store && *ep_store) {
			/* Remove the old encapsulation entry first. */
			encap_detach(*ep_store);
			*ep_store = NULL;
		}

		bzero(&src, sizeof(src));
		src.sin6_family = AF_INET6;
		src.sin6_len = sizeof(struct sockaddr_in6);
		src.sin6_addr = *ip6_src;

		in6_prefixlen2mask(&mask, mask_len);
		bzero(&srcm, sizeof(srcm));
		srcm.sin6_family = AF_INET6;
		srcm.sin6_len = sizeof(struct sockaddr_in6);
		srcm.sin6_addr = mask;

		bzero(&dst, sizeof(dst));
		dst.sin6_family = AF_INET6;
		dst.sin6_len = sizeof(struct sockaddr_in6);
		dst.sin6_addr = *ip6_dst;

		in6_prefixlen2mask(&mask, mask_len);
		bzero(&dstm, sizeof(dstm));
		dstm.sin6_family = AF_INET6;
		dstm.sin6_len = sizeof(struct sockaddr_in6);
		dstm.sin6_addr = mask;

		ep = encap_attach(AF_INET6, -1,
				  (struct sockaddr *)&src,
				  (struct sockaddr *)&srcm,
				  (struct sockaddr *)&dst,
				  (struct sockaddr *)&dstm,
				  (struct protosw *)&mip6_tunnel_protosw,
				  NULL);
		if (ep == NULL)
			return EINVAL;
		*ep_store = ep;
		return 0;
	}
	return EINVAL;
}



/*
 ******************************************************************************
 * Function:    mip6_proxy
 * Description: Set or delete address to act proxy for.
 * Ret value:   Standard error codes.
 ******************************************************************************
 */
int
mip6_proxy(struct in6_addr* addr,
	   struct in6_addr* local,
	   int cmd)
{
	struct sockaddr_in6	mask /* = {sizeof(mask), AF_INET6 }*/;
	struct sockaddr_in6	sa6;
	struct sockaddr_dl	*sdl;
	struct ifaddr		*ifa;
	struct ifnet		*ifp;
	int			flags, error;
        struct rtentry		*nrt;

	if (cmd == RTM_DELETE) {
		struct rtentry *rt;

		bzero(&sa6, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		sa6.sin6_len = sizeof(sa6);
		sa6.sin6_addr = *addr;

#ifdef __FreeBSD__ || defined (__APPLE__)
		rt = rtalloc1((struct sockaddr *)&sa6, 1, 0UL);
#else
		rt = rtalloc1((struct sockaddr *)&sa6, 1);
#endif
		if (rt == NULL)
			return EHOSTUNREACH;

		error = rtrequest(RTM_DELETE, rt_key(rt), (struct sockaddr *)0,
				  rt_mask(rt), 0, (struct rtentry **)0);
		rt->rt_refcnt--;
		rt = NULL;
		return error;
	}
		
	/* Create sa6 */
	bzero(&sa6, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_len = sizeof(sa6);
	sa6.sin6_addr = *local;

	ifa = ifa_ifwithaddr((struct sockaddr *)&sa6);
	if (ifa == NULL)
		return EINVAL;

	sa6.sin6_addr = *addr;

	/* Create sdl */
	ifp = ifa->ifa_ifp;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
        for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#else
        for (ifa = ifp->if_addrlist.tqh_first; ifa;
	     ifa = ifa->ifa_list.tqe_next)
#endif
                if (ifa->ifa_addr->sa_family == AF_LINK)
			break;

	if (!ifa)
		return EINVAL;

	MALLOC(sdl, struct sockaddr_dl *, ifa->ifa_addr->sa_len, M_IFMADDR,
	       M_WAITOK);
	bcopy((struct sockaddr_dl *)ifa->ifa_addr, sdl, ifa->ifa_addr->sa_len);

	/* Create mask */
	bzero(&mask, sizeof(mask));
	mask.sin6_family = AF_INET6;
	mask.sin6_len = sizeof(mask);

	in6_len2mask(&mask.sin6_addr, 128);

	flags = (RTF_STATIC | RTF_ANNOUNCE | RTA_NETMASK);

	error = rtrequest(RTM_ADD, (struct sockaddr *)&sa6,
			  (struct sockaddr *)sdl,
			  (struct sockaddr *)&mask, flags, &nrt);

	if (error == 0) {
		/* avoid expiration */
		if (nrt) {
			nrt->rt_rmx.rmx_expire = 0;
			nrt->rt_genmask = NULL;
			nrt->rt_refcnt--;
		}
		else
			error = EINVAL;
	}
	_FREE(sdl, M_IFMADDR);
	return error;
}



/*
 ##############################################################################
 #
 # LIST FUNCTIONS
 # The correspondent node maintains a Binding Cache list for each node from
 # which it has received a BU.
 # It also maintains a list of Neighbor Advertisements that shall be sent
 # either by the home agent when start acting as a proxy for the mobile node
 # or by the mobile node when returning to the home network.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_bc_find
 * Description: Find an entry in the Binding Cache list.
 * Ret value:   Pointer to Binding Cache entry or NULL if no entry found.
 ******************************************************************************
 */
struct mip6_bc *
mip6_bc_find(home_addr)
struct in6_addr  *home_addr;  /* Home Address of the MN for which the BC
                                 entry is searched */
{
	struct mip6_bc  *bcp;     /* Entry in the Binding Cache list */

	for (bcp = mip6_bcq; bcp; bcp = bcp->next) {
		if (IN6_ARE_ADDR_EQUAL(home_addr, &bcp->home_addr))
			return bcp;
	}
	return NULL;
}



/*
 ******************************************************************************
 * Function:    mip6_bc_create
 * Description: Create a new Binding Cache entry, add it first to the Binding
 *              Cache list and set parameters for the entry.
 * Ret value:   Pointer to the created BC entry or NULL.
 * Note 1:      If the BC timeout function has not been started it is started.
 *              The BC timeout function will be called once every second until
 *              there are no more entries in the BC list.
 * Note 2:      The gif i/f is created/updated in function mip6_tunnel and
 *              should not be taken care of here.
 ******************************************************************************
 */
struct mip6_bc *
mip6_bc_create(home_addr, coa, lifetime, hr, rtr, prefix_len, seqno)
struct in6_addr  *home_addr;  /* Home Address for the mobile node */
struct in6_addr  *coa;        /* COA for the mobile node */
u_int32_t        lifetime;    /* Remaining lifetime for this BC entry */
u_int8_t         hr;          /* Flag for home registration (0/1) */
u_int8_t         rtr;         /* MN is router (0/1) */
u_int8_t         prefix_len;  /* Prefix length for Home Address */
u_int16_t        seqno;       /* Sequence number in the received BU */
{
	struct mip6_bc  *bcp;     /* Created BC list entry*/
	int    s;

	bcp = (struct mip6_bc *)MALLOC mip6_bc),
				       M_TEMP, M_WAITOK);
	if (bcp == NULL)
		return NULL;
	bzero((caddr_t)bcp, sizeof(struct mip6_bc));

	bcp->next = NULL;
	bcp->home_addr = *home_addr;
	bcp->coa = *coa;
	bcp->lifetime = lifetime;
	bcp->hr_flag = hr;
	bcp->prefix_len = prefix_len;
	bcp->seqno = seqno;
	bcp->lasttime = 0;
	bcp->ep = NULL;

	if (bcp->hr_flag)
		bcp->rtr_flag = rtr;
	else {
		bcp->rtr_flag = 0;

		if (mip6_config.br_update > 60)
			bcp->info.br_interval = 60;
		else if (mip6_config.br_update < 2)
			bcp->info.br_interval = 2;
		else
			bcp->info.br_interval = mip6_config.br_update;
	}

	/* Insert the entry as the first entry in the Binding Cache list. */
	s = splnet();
	if (mip6_bcq == NULL) {
		mip6_bcq = bcp;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_bc_handle =
#endif
			timeout(mip6_timer_bc, (void *)0, hz);
	} else {
		bcp->next = mip6_bcq;
		mip6_bcq = bcp;
	}
	splx(s);

#if MIP6_DEBUG
	mip6_debug("\nBinding Cache Entry created (0x%x)\n", bcp);
	mip6_debug("Home Addr/Prefix len: %s / %u\n",
		   ip6_sprintf(&bcp->home_addr), bcp->prefix_len);
	mip6_debug("Care-of Address:      %s\n", ip6_sprintf(&bcp->coa));
	mip6_debug("Remaining lifetime:   %u\n", bcp->lifetime);
	mip6_debug("Sequence number:      %u\n", bcp->seqno);
	mip6_debug("Home reg/Router:      ");
	if (bcp->hr_flag)
		mip6_debug("TRUE / ");
	else
		mip6_debug("FALSE / ");

	if (bcp->rtr_flag)
		mip6_debug("TRUE\n");
	else
		mip6_debug("FALSE\n");
#endif
	return bcp;
}



/*
 ******************************************************************************
 * Function:    mip6_bc_update
 * Description: Update an existing Binding Cache entry
 * Ret value:   -
 * Note:        The gif i/f is created/updated in function mip6_tunnel and
 *              should not be taken care of here.
 ******************************************************************************
 */
void
mip6_bc_update(bcp, coa, lifetime, hr, rtr, prefix_len, seqno, info, lasttime)
struct mip6_bc   *bcp;        /* BC entry being allocated or updated */
struct in6_addr  *coa;        /* COA for the mobile node */
u_int32_t        lifetime;    /* Remaining lifetime for this BC entry */
u_int8_t         hr;          /* Flag for home registration (0/1) */
u_int8_t         rtr;         /* MN is router (0/1) */
u_int8_t         prefix_len;  /* Prefix length for Home Address */
u_int16_t        seqno;       /* Sequence number in the received BU */
struct bc_info   info;        /* Usage info for cache replacement policy */
time_t           lasttime;    /* The time at which a BR was last sent */
{
	bcp->coa = *coa;
	bcp->lifetime = lifetime;
	bcp->hr_flag = hr;
	bcp->prefix_len = prefix_len;
	bcp->seqno = seqno;

	if (bcp->hr_flag) {
		bcp->rtr_flag = rtr;
		bzero((caddr_t)&bcp->info, sizeof(struct bc_info));
	} else {
		bcp->rtr_flag = 0;

		if (info.br_interval > 60)
			bcp->info.br_interval = 60;
		else if (info.br_interval < 2)
			bcp->info.br_interval = 2;
		else
			bcp->info.br_interval = info.br_interval;
	}
	bcp->lasttime = lasttime;

#if MIP6_DEBUG
	mip6_debug("\nBinding Cache Entry updated (0x%x)\n", bcp);
	mip6_debug("Home Addr/Prefix len: %s / %u\n",
		   ip6_sprintf(&bcp->home_addr), bcp->prefix_len);
	mip6_debug("Care-of Address:      %s\n", ip6_sprintf(&bcp->coa));
	mip6_debug("Remaining lifetime:   %u\n", bcp->lifetime);
	mip6_debug("Sequence number:      %u\n", bcp->seqno);
	mip6_debug("Home reg/Router:      ");
	if (bcp->hr_flag)
		mip6_debug("TRUE / ");
	else
		mip6_debug("FALSE / ");

	if (bcp->rtr_flag)
		mip6_debug("TRUE\n");
	else
		mip6_debug("FALSE\n");
#endif
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_bc_delete
 * Description: Delete an entry in the Binding Cache list.
 * Ret value:   Error code
 *              Pointer to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
int
mip6_bc_delete(bcp_del, bcp_nxt)
struct mip6_bc  *bcp_del;  /* Pointer to BC entry to delete */
struct mip6_bc **bcp_nxt;  /* Returns next entry in the list */
{
	struct mip6_bc  *bcp;       /* Current entry in the BC list */
	struct mip6_bc  *bcp_prev;  /* Previous entry in the BC list */
	struct mip6_bc  *bcp_next;  /* Next entry in the BC list */
	int              s, error = 0;

	s = splnet();
	bcp_prev = NULL;
	bcp_next = NULL;
	for (bcp = mip6_bcq; bcp; bcp = bcp->next) {
		bcp_next = bcp->next;
		if (bcp != bcp_del) {
			bcp_prev = bcp;
			continue;
		}
		
		/* Make sure that the list pointers are correct. */
		if (bcp_prev == NULL)
			mip6_bcq = bcp->next;
		else
			bcp_prev->next = bcp->next;

		if (bcp->hr_flag) {	
			/* The HA should stop acting as a proxy for the MN. */
			error = mip6_proxy(&bcp->home_addr, NULL, RTM_DELETE);
			if (error) {
#if MIP6_DEBUG
				mip6_debug("%s: delete proxy error = %d\n",
					   __FUNCTION__, error);
#endif
				*bcp_nxt = bcp_next;
				return error;
			}

			/* Delete the existing tunnel to the MN. */
			mip6_tunnel(NULL, NULL, MIP6_TUNNEL_DEL, MIP6_NODE_HA,
				    (void *)bcp);
		}

#if MIP6_DEBUG
		mip6_debug("\nBinding Cache Entry deleted (0x%x)\n", bcp);
#endif
		_FREE(bcp, M_TEMP);

		/* Remove the timer if the BC queue is empty */
		if (mip6_bcq == NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
			untimeout(mip6_timer_bc, (void *)NULL,
				  mip6_timer_bc_handle);
			callout_handle_init(&mip6_timer_bc_handle);
#else
			untimeout(mip6_timer_bc, (void *)NULL);
#endif
		}
		break;
	}
	splx(s);
	
	*bcp_nxt = bcp_next;
	return error;
}



/*
 ******************************************************************************
 * Function:    mip6_na_create
 * Description: Create a NA entry and add it to the list of Neighbor Adver-
 *              tisements. The NA will be repeateadly sent by either the
 *              Mobile Node when returning to its home link or by the Home
 *              Agent when acting as a proxy for a Mobile Node while away
 *              from its home network.
 * Note:        The first Neighbor Advertisement is sent by this function.
 * Ret value:   Pointer to the created entry or NULL in case of error.
 ******************************************************************************
 */
struct mip6_na *
mip6_na_create(home_addr, dst_addr, target_addr, prefix_len,
               flags, use_link_opt)
struct in6_addr  *home_addr;    /* Home address of the mobile node */
struct in6_addr  *dst_addr;     /* Destination address */
struct in6_addr  *target_addr;  /* Target address */
u_int8_t         prefix_len;    /* Prefix length of the home address */
u_long           flags;         /* Flags for the NA message */
int              use_link_opt;  /* Include Target link layer address option or
                                   not (0 = Do not include, 1 = Include) */
{
	struct mip6_na        *nap;   /* Created NA message */
	struct mip6_link_list *llp;   /* Link list entry */
	struct mip6_ha_list   *halp;  /* Home agent list entry */
	struct mip6_addr_list *addrp; /* Address list entry */
	struct nd_prefix      *pr;    /* Prefix list entry */
	int    s, start_timer = 0;

	llp = NULL;
	halp = NULL;
	addrp = NULL;
	pr = NULL;

	if (mip6_naq == NULL)
		start_timer = 1;

	nap = (struct mip6_na *)MALLOC mip6_na),
				       M_TEMP, M_WAITOK);
	if (nap == NULL)
		return NULL;
	bzero(nap, sizeof(struct mip6_na));

	nap->next = NULL;
	nap->home_addr = *home_addr;
	nap->dst_addr = *dst_addr;
	nap->target_addr = *target_addr;
	nap->prefix_len = prefix_len;
	nap->flags = flags;
	nap->use_link_opt = use_link_opt;
	nap->no = MIP6_MAX_ADVERT_REXMIT;

	/* The interface that shall be used may not be assumed to be the
	   interface of the incoming packet, but must be the interface stated
	   in the prefix that matches the home address. */
	if (MIP6_IS_HA_ACTIVE) {
		for (llp = mip6_llq; llp; llp = llp->next) {
			for (halp = llp->ha_list; halp; halp = halp->next) {
				for (addrp = halp->addr_list; addrp;
				     addrp = addrp->next) {
					if (in6_are_prefix_equal(
						home_addr,
						&addrp->ip6_addr,
						addrp->prefix_len))
						break;
				}
				if (addrp != NULL)
					break;
			}
			if (addrp != NULL)
				break;
		}
		if (addrp == NULL) {
			log(LOG_ERR,
			    "%s: No interface found for sending Neighbor "
			    "Advertisements at\n", __FUNCTION__);
			return NULL;
		}
		nap->ifp = llp->ifp;
	}

	if (MIP6_IS_MN_ACTIVE) {
		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
			if (!pr->ndpr_stateflags.onlink)
				continue;
			if (in6_are_prefix_equal(home_addr,
						 &pr->ndpr_prefix.sin6_addr,
						 pr->ndpr_plen))
				break;
		}
		if (pr == NULL) {
			log(LOG_ERR,
			    "%s: No interface found for sending Neighbor "
			    "Advertisements at\n", __FUNCTION__);
			return NULL;
		}
		nap->ifp = pr->ndpr_ifp;
	}

	/* Add the new na entry first to the list. */
	s = splnet();
	nap->next = mip6_naq;
	mip6_naq = nap;
	splx(s);

#if MIP6_DEBUG
	mip6_debug("\nCreated Neighbor Advertisement List entry (0x%x)\n",
		   nap);
	mip6_debug("Interface being used: %s\n", if_name(nap->ifp));
	mip6_debug("Home Addr/Prefix len: %s / %d\n",
		   ip6_sprintf(&nap->home_addr), nap->prefix_len);
	mip6_debug("Destination Address:  %s\n", ip6_sprintf(&nap->dst_addr));
	mip6_debug("Target Address:       %s\n",
		   ip6_sprintf(&nap->target_addr));
	if (nap->use_link_opt)
		mip6_debug("Incl Target ll_addr : TRUE\n");
	else
		mip6_debug("Incl Target ll_addr : FALSE\n");
#endif

	/* Send the Neighbor Advertisment entry to speed up cache changes. */
	mip6_send_na(nap);

	if (start_timer) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_na_handle =
#endif
			timeout(mip6_timer_na, (void *)0, hz);
	}
	return nap;
}



/*
 ******************************************************************************
 * Function:    mip6_na_delete
 * Description: Delete an entry in the NA list.
 * Ret value:   Pointer to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
struct mip6_na *
mip6_na_delete(nap_del)
struct mip6_na  *nap_del;  /* Pointer to NA entry to delete */
{
	struct mip6_na   *nap;       /* Current entry in the NA list */
	struct mip6_na   *nap_prev;  /* Previous entry in the NA list */
	struct mip6_na   *nap_next;  /* Next entry in the NA list */
	int    s;

	s = splnet();
	nap_prev = NULL;
	nap_next = NULL;
	for (nap = mip6_naq; nap; nap = nap->next) {
		nap_next = nap->next;
		if (nap == nap_del) {
			if (nap_prev == NULL)
				mip6_naq = nap->next;
			else
				nap_prev->next = nap->next;

#if MIP6_DEBUG
			mip6_debug("\nNeighbor Advertisement Entry "
				   "deleted (0x%x)\n", nap);
#endif
			_FREE(nap, M_TEMP);

			/* Remove the timer if the NA queue is empty */
			if (mip6_naq == NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
				untimeout(mip6_timer_na, (void *)NULL,
					  mip6_timer_na_handle);
				callout_handle_init(&mip6_timer_na_handle);
#else
				untimeout(mip6_timer_na, (void *)NULL);
#endif
			}
			break;
		}
		nap_prev = nap;
	}
	splx(s);
	return nap_next;
}



/*
 ******************************************************************************
 * Function:    mip6_prefix_find
 * Description: Try to find an existing prefix entry in the prefix list.
 * Ret value:   Pointer to found prefix list entry or NULL.
 ******************************************************************************
 */
struct mip6_prefix *
mip6_prefix_find(prefix, prefix_len)
struct in6_addr  *prefix;      /* Prefix to search for */
u_int8_t          prefix_len;  /* Prefix length */
{
	struct mip6_prefix  *pq;

	for (pq = mip6_pq; pq; pq = pq->next) {
		if (in6_are_prefix_equal(&pq->prefix, prefix, prefix_len))
			return pq;
	}
	return NULL;
}



/*
 ******************************************************************************
 * Function:    mip6_prefix_create
 * Description: Create a prefix and add it as the first entry in the list.
 *              Start the timer if not started already.
 * Ret value:   Pointer to created prefix list entry or NULL.
 ******************************************************************************
 */
struct mip6_prefix *
mip6_prefix_create(ifp, prefix, prefix_len, valid_time)
struct ifnet     *ifp;         /* Outgoing interface */
struct in6_addr  *prefix;      /* Prefix to search for */
u_int8_t          prefix_len;  /* Prefix length */
u_int32_t         valid_time;  /* Time (s) that the prefix is valid */
{
	struct mip6_prefix  *pq;
	int    s, start_timer = 0;

	if (mip6_pq == NULL)
		start_timer = 1;

	pq = (struct mip6_prefix *)MALLOC mip6_prefix),
					  M_TEMP, M_WAITOK);
	if (pq == NULL)
		return NULL;
	bzero(pq, sizeof(struct mip6_prefix));

	s = splnet();
	pq->next = mip6_pq;
	pq->ifp = ifp;
	pq->prefix = *prefix;
	pq->prefix_len = prefix_len;
	pq->valid_time = valid_time;
	mip6_pq = pq;
	splx(s);

#if MIP6_DEBUG
	mip6_debug("\nInternal Prefix list entry created (0x%x)\n", pq);
	mip6_debug("Interface:  %s\n", if_name(ifp));
	mip6_debug("Prefix:     %s\n", ip6_sprintf(&pq->prefix));
	mip6_debug("Prefix len: %d\n", pq->prefix_len);
	mip6_debug("Life time:  %d\n", htonl(pq->valid_time));
#endif

	if (start_timer) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_prefix_handle =
#endif
			timeout(mip6_timer_prefix, (void *)0, hz);
	}
	return pq;
}



/*
 ******************************************************************************
 * Function:    mip6_prefix_delete
 * Description: Delete the requested prefix list entry.
 * Ret value:   Ptr to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
struct mip6_prefix *
mip6_prefix_delete(pre_del)
struct mip6_prefix  *pre_del;    /* Prefix list entry to be deleted */
{
	struct mip6_prefix  *pre;       /* Current entry in the list */
	struct mip6_prefix  *pre_prev;   /* Previous entry in the list */
	struct mip6_prefix  *pre_next;   /* Next entry in the list */
	int    s;

	/* Find the requested entry in the link list. */
	s = splnet();
	pre_next = NULL;
	pre_prev = NULL;
	for (pre = mip6_pq; pre; pre = pre->next) {
		pre_next = pre->next;
		if (pre == pre_del) {
			if (pre_prev == NULL)
				mip6_pq = pre->next;
			else
				pre_prev->next = pre->next;

#if MIP6_DEBUG
			mip6_debug("\nMIPv6 prefix entry deleted (0x%x)\n", pre);
#endif
			_FREE(pre, M_TEMP);

			/* Remove the timer if the prefix queue is empty */
			if (mip6_pq == NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
				untimeout(mip6_timer_prefix, (void *)NULL,
					  mip6_timer_prefix_handle);
				callout_handle_init(&mip6_timer_prefix_handle);
#else
				untimeout(mip6_timer_prefix, (void *)NULL);
#endif
			}
			break;
		}
		pre_prev = pre;
	}
	splx(s);
	return pre_next;
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
 * Function:    mip6_timer_na
 * Description: Called once every second. For each entry in the list a Neighbor
 *              Advertisement is sent until the counter value reaches 0. Then
 *              the entry is removed.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_na(arg)
void  *arg;  /* Not used */
{
	struct mip6_na     *nap;      /* Neighbor Advertisement entry */
	int                 s;
#ifdef __APPLE__
	boolean_t   funnel_state;
    	funnel_state = thread_set_funneled(TRUE);
#endif

	/* Go through the entire list of Neighbor Advertisement entries. */
	s = splnet();
	for (nap = mip6_naq; nap;) {
		mip6_send_na(nap);
		if (nap->no <= 0)
			nap = mip6_na_delete(nap);
		else
			nap = nap->next;
	}
	splx(s);

	if (mip6_naq != NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_na_handle =
#endif
			timeout(mip6_timer_na, (void *)0, hz);
	}
#ifdef __APPLE__
    (void) thread_set_funneled(funnel_state);
#endif
}



/*
 ******************************************************************************
 * Function:    mip6_timer_bc
 * Description: Called once every second. For each entry in the BC list, a
 *              counter is reduced by 1 until it reaches the value of zero,
 *              then the entry is removed.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_bc(arg)
void  *arg;  /* Not used */
{
	struct mip6_bc  *bcp;      /* Current entry in the BC list */
	struct mip6_bc  *bcp_nxt;  /* Next BC list entry */
	int              s;
#ifdef __APPLE__
	boolean_t   funnel_state;
    	funnel_state = thread_set_funneled(TRUE);
#endif

	/* Go through the entire list of Binding Cache entries. */
	s = splnet();
	for (bcp = mip6_bcq; bcp;) {
		bcp->lifetime -= 1;
		if (bcp->lifetime == 0) {
			mip6_bc_delete(bcp, &bcp_nxt);
			bcp = bcp_nxt;
		} else
			bcp = bcp->next;
	}
	splx(s);

	/* XXX */
	/* Code have to be added to take care of bc_info.br_interval
	   variable. */
	/* We have to send a BR when the mip6_bc.lifetime ==
	   mip6_bc.bc_info.br_interval. */
	if (mip6_bcq != NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_bc_handle =
#endif
			timeout(mip6_timer_bc, (void *)0, hz);
	}
#ifdef __APPLE__
    	(void) thread_set_funneled(funnel_state);
#endif
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_timer_prefix
 * Description: Called once every second. Search the list of prefixes and if
 *              a prefix has timed out it is removed from the list.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_prefix(arg)
void  *arg;  /* Not used */
{
	struct mip6_prefix  *pq_entry;   /* Current entry in the prefix list */
	int                  s;
#ifdef __APPLE__
	boolean_t   funnel_state;
    	funnel_state = thread_set_funneled(TRUE);
#endif

	/* Go through the entire list of prefix entries. */
	s = splnet();
	for (pq_entry = mip6_pq; pq_entry;) {
		pq_entry->valid_time -= 1;
		if (pq_entry->valid_time == 0)
			pq_entry = mip6_prefix_delete(pq_entry);
		else
			pq_entry = pq_entry->next;
	}
	splx(s);

	if (mip6_pq != NULL) {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		mip6_timer_prefix_handle =
#endif
			timeout(mip6_timer_prefix, (void *)0, hz);
	}
#ifdef __APPLE__
	(void) thread_set_funneled(funnel_state);
#endif
	return;
}



/*
 ##############################################################################
 #
 # IOCTL AND DEBUG FUNCTIONS
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_ioctl
 * Description: The ioctl handler for MIPv6. These are used by the
 *              configuration program to set and get various parameters.
 * Ret value:   0 or error code
 ******************************************************************************
 */
int
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
mip6_ioctl(so, cmd, data, ifp, p)
struct  socket *so;
u_long          cmd;
caddr_t         data;
struct ifnet   *ifp;
struct proc    *p;
#else
mip6_ioctl(so, cmd, data, ifp)
struct  socket *so;
u_long          cmd;
caddr_t         data;
struct ifnet   *ifp;
#endif
{
	int res;

	/* Note: privileges already checked in in6_control(). */

	res = 0;
	switch (cmd) {
	case SIOCSBCFLUSH_MIP6:
	case SIOCSDEFCONFIG_MIP6:
		res = mip6_clear_config_data(cmd, data);
		return res;

	case SIOCSBRUPDATE_MIP6:
		res = mip6_write_config_data(cmd, data);
		return res;

	case SIOCSHAPREF_MIP6:
		/* Note: this one can be run before attach. */
		if (mip6_write_config_data_ha_hook)
			res = (*mip6_write_config_data_ha_hook)
				(cmd, data);
		break;

	case SIOCACOADDR_MIP6:
	case SIOCAHOMEADDR_MIP6:
	case SIOCSBULIFETIME_MIP6:
	case SIOCSHRLIFETIME_MIP6:
	case SIOCDCOADDR_MIP6:
		/* Note: these can be run before attach. */
		if (mip6_write_config_data_mn_hook)
			res = (*mip6_write_config_data_mn_hook)
				(cmd, data);
		break;

	case SIOCSDEBUG_MIP6:
	case SIOCSENABLEBR_MIP6:
	case SIOCSATTACH_MIP6:
		res = mip6_enable_func(cmd, data);
		return res;

	case SIOCSFWDSLUNICAST_MIP6:
	case SIOCSFWDSLMULTICAST_MIP6:
		/* Note: these can be run before attach. */
		if (mip6_enable_func_ha_hook)
			res = (*mip6_enable_func_ha_hook)(cmd, data);
		break;

	case SIOCSPROMMODE_MIP6:
	case SIOCSBU2CN_MIP6:
	case SIOCSREVTUNNEL_MIP6:
	case SIOCSAUTOCONFIG_MIP6:
	case SIOCSEAGERMD_MIP6:
		/* Note: these can be run before attach. */
		if (mip6_enable_func_mn_hook)
			res = (*mip6_enable_func_mn_hook)(cmd, data);
		break;

	case SIOCSRELEASE_MIP6:
		mip6_release();
		return res;

	default:
		res = EOPNOTSUPP;
		break;
	}

	if (MIP6_IS_HA_ACTIVE) {
		res = 0;
		switch (cmd) {
		case SIOCSHALISTFLUSH_MIP6:
			if (mip6_clear_config_data_ha_hook)
				res = (*mip6_clear_config_data_ha_hook)
					(cmd, data);
			break;

		default:
			res = EOPNOTSUPP;
			break;
		}
	}

	if (MIP6_IS_MN_ACTIVE) {
		res = 0;
		switch (cmd) {
		case SIOCSFORADDRFLUSH_MIP6:
		case SIOCSHADDRFLUSH_MIP6:
		case SIOCSBULISTFLUSH_MIP6:
			if (mip6_clear_config_data_mn_hook)
				res = (*mip6_clear_config_data_mn_hook)
					(cmd, data);
			break;

		default:
			res = EOPNOTSUPP;
			break;
		}
	}
	if (res) {
#if MIP6_DEBUG
		printf("%s: unknown command: %lu\n", __FUNCTION__, (u_long)cmd);
#endif
	}
	return res;
}



/*
 ******************************************************************************
 * Function:    mip6_debug
 * Description: This function displays MIPv6 debug messages to the console
 *              if activated with the configuration program. Note that this
 *              is included only when "options MIP6_DEBUG" is defined.
 * Ret value:   -
 ******************************************************************************
 */
#if MIP6_DEBUG
void mip6_debug(char *fmt, ...)
{
#ifndef __bsdi__
	va_list ap;

	if (!mip6_debug_is_enabled)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
#endif
}



void
mip6_enable_debug(int status)
{
	mip6_debug_is_enabled = status;
}
#endif /* MIP6_DEBUG */



/*
 ******************************************************************************
 * Function:    mip6_write_config_data
 * Description: This function is called to write certain config values for
 *              MIPv6. The data is written into the global config structure.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_write_config_data(u_long cmd, caddr_t data)
{
	int  retval = 0;

	switch (cmd) {
        case SIOCSBRUPDATE_MIP6:
		mip6_config.br_update = *(u_int8_t *)data;
		break;
	}
	return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_clear_config_data
 * Description: This function is called to clear internal lists handled by
 *              MIPv6.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_clear_config_data(u_long cmd, caddr_t data)
{
	int             s, retval = 0;
	struct mip6_bc *bcp, *bcp_nxt;

	s = splnet();
	switch (cmd) {
	case SIOCSBCFLUSH_MIP6:
		for (bcp = mip6_bcq; bcp;) {
			if(!bcp->hr_flag) {
				mip6_bc_delete(bcp, &bcp_nxt);
				bcp = bcp_nxt;
			} else
				bcp = bcp->next;
		}
		break;

	case SIOCSDEFCONFIG_MIP6:
		mip6_config.bu_lifetime = 600;
		mip6_config.br_update = 60;
		mip6_config.hr_lifetime = 3600;
		mip6_config.enable_outq = 1;
		break;
	}
	splx(s);
	return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_enable_func
 * Description: This function is called to enable or disable certain functions
 *              in mip6. The data is written into the global config struct.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_enable_func(u_long cmd, caddr_t data)
{
	int enable;
	int retval = 0;

	enable = ((struct mip6_input_data *)data)->value;

	switch (cmd) {
	case SIOCSDEBUG_MIP6:
#if MIP6_DEBUG
		mip6_enable_debug(enable);
#else
		printf("No Mobile IPv6 debug information available!\n");
#endif
		break;

	case SIOCSENABLEBR_MIP6:
		mip6_config.enable_br = enable;
		break;

	case SIOCSATTACH_MIP6:
		printf("%s: attach %d\n", __FUNCTION__, enable); /* RM */
		retval = mip6_attach(enable);
		break;
	}
	return retval;
}
