/*	$KAME: mip6_io.c,v 1.7 2000/03/25 07:23:53 sumikawa Exp $	*/

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
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>


void (*mip6_icmp6_output_hook)(struct mbuf *) = 0;
struct mip6_esm * (*mip6_esm_find_hook)(struct in6_addr *) = 0;


/* Declaration of Global variables. */
struct mip6_indata  *mip6_inp = NULL;
struct mip6_output  *mip6_outq = NULL;



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
 * Function:    mip6_new_packet
 * Description: Called once when a new IPv6 packet is received. Resets the
 *              mip6_inp variable needed later when options in the dest-
 *              ination header are validated.
 * Ret value:   0 if OK. Otherwise IPPROTO_DONE.
 * Note:        A prerequisite for this function is that the AH or ESP header
 *              is included in the same IPv6 packet as the destination header,
 *              i.e we are using transport mode and not tunneling mode.
 ******************************************************************************
 */
int
mip6_new_packet(m)
struct mbuf  *m;   /* Mbuf containing IPv6 header */
{
    /* If memory for global variable mip6_indata already allocated,
       discard it. */
    if (mip6_inp != NULL) {
        if (mip6_inp->bu_opt != NULL)
            FREE(mip6_inp->bu_opt, M_TEMP);
        if (mip6_inp->ba_opt != NULL)
            FREE(mip6_inp->ba_opt, M_TEMP);
        if (mip6_inp->br_opt != NULL)
            FREE(mip6_inp->br_opt, M_TEMP);
        if (mip6_inp->ha_opt != NULL)
            FREE(mip6_inp->ha_opt, M_TEMP);
        if (mip6_inp->uid != NULL)
            FREE(mip6_inp->uid, M_TEMP);
        if (mip6_inp->coa != NULL)
            FREE(mip6_inp->coa, M_TEMP);
        if (mip6_inp->hal != NULL)
            FREE(mip6_inp->hal, M_TEMP);
        FREE(mip6_inp, M_TEMP);
        mip6_inp = NULL;
    }

    /* Allocate memory for global variable mip6_inp */
    mip6_inp = (struct mip6_indata *)
        MALLOC(sizeof(struct mip6_indata), M_TEMP, M_WAITOK);
    if (mip6_inp == NULL)
        panic("%s: We should not come here !!!!", __FUNCTION__);
    bzero(mip6_inp, sizeof(struct mip6_indata));

    return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_store_dstopt_pre
 * Description: Pre-processing used by the hook function.
 * Ret value:   0 if OK. Otherwise IPPROTO_DONE
 ******************************************************************************
 */
int
mip6_store_dstopt_pre(m, opt, off, dstlen)
struct mbuf  *m;      /* Pointer to the beginning of mbuf */
u_int8_t     *opt;    /* Pointer to the beginning of current option in mbuf */
u_int8_t     off;     /* Offset from beginning of mbuf to end of dest header */
u_int8_t     dstlen;  /* Remaining length of Destination header */
{
    u_int8_t type;    /* Destination option type */

    type = *opt;
    if (type == IP6OPT_BINDING_UPDATE) {
        if (dstlen < IP6OPT_BUMINLEN) {
            ip6stat.ip6s_toosmall++;
            return IPPROTO_DONE;
        }

        if (mip6_store_dstopt(m, opt, off-dstlen) != 0)
            return IPPROTO_DONE;
    } else if (type == IP6OPT_BINDING_ACK) {
        if (dstlen < IP6OPT_BAMINLEN) {
            ip6stat.ip6s_toosmall++;
            return IPPROTO_DONE;
        }

        if (mip6_store_dstopt(m, opt, off-dstlen) != 0)
            return IPPROTO_DONE;
    } else if (type == IP6OPT_BINDING_REQ) {
        if (dstlen < IP6OPT_BRMINLEN) {
            ip6stat.ip6s_toosmall++;
            return IPPROTO_DONE;
        }

        if (mip6_store_dstopt(m, opt, off-dstlen) != 0)
            return IPPROTO_DONE;
    } else if (type == IP6OPT_HOME_ADDRESS) {
        if (dstlen < IP6OPT_HAMINLEN) {
            ip6stat.ip6s_toosmall++;
            return IPPROTO_DONE;
        }

        if (mip6_store_dstopt(m, opt, off-dstlen) != 0)
            return IPPROTO_DONE;
    }

    return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_store_dstopt
 * Description: Save each MIPv6 option from the Destination header continously.
 *              They will be evaluated when the entire destination header has
 *              been read.
 * Ret value:   0 if OK
 *              Otherwise protocol error code from netinet/in.h
 ******************************************************************************
 */
int
mip6_store_dstopt(mp, opt, optoff)
struct mbuf  *mp;     /* Pointer to the beginning of mbuf */
u_int8_t     *opt;    /* Pointer to the beginning of current option in mbuf */
u_int8_t     optoff;  /* Offset from beginning of mbuf to start of current
                         option */
{
    struct mip6_opt_bu  *bu_opt;    /* Ptr to BU option data */
    struct mip6_opt_ba  *ba_opt;    /* Ptr to BA option data */
    struct mip6_opt_br  *br_opt;    /* Ptr to BR option data */
    struct mip6_opt_ha  *ha_opt;    /* Ptr to HA option data */
    int    tmplen;      /* Tmp length for positioning in option */
    int    totlen;      /* Total length of option + sub-option */
    int    error;

    /* Find out what kind of buffer we are dealing with */
    switch (*opt) {
        case IP6OPT_BINDING_UPDATE:
            /* Allocate and store Binding Update option data */
            mip6_inp->bu_opt = (struct mip6_opt_bu *)
                MALLOC(sizeof(struct mip6_opt_bu), M_TEMP, M_WAITOK);
            if (mip6_inp->bu_opt == NULL)
                return ENOBUFS;
            bzero(mip6_inp->bu_opt, sizeof(struct mip6_opt_bu));

            bu_opt = mip6_inp->bu_opt;
	    m_copydata(mp, optoff, sizeof(bu_opt->type),
	        (caddr_t)&bu_opt->type);
            tmplen = sizeof(bu_opt->type);
            m_copydata(mp, optoff + tmplen, sizeof(bu_opt->len),
                (caddr_t)&bu_opt->len);
            tmplen += sizeof(bu_opt->len);
            m_copydata(mp, optoff + tmplen, sizeof(bu_opt->flags),
                (caddr_t)&bu_opt->flags);
            tmplen += sizeof(bu_opt->flags);
	    m_copydata(mp, optoff + tmplen, sizeof(bu_opt->prefix_len),
		(caddr_t)&bu_opt->prefix_len);
            tmplen += sizeof(bu_opt->prefix_len);
	    m_copydata(mp, optoff + tmplen, sizeof(bu_opt->seqno),
                (caddr_t)&bu_opt->seqno);
            tmplen += sizeof(bu_opt->seqno);
	    m_copydata(mp, optoff + tmplen, sizeof(bu_opt->lifetime),
                (caddr_t)&bu_opt->lifetime);
            tmplen += sizeof(bu_opt->lifetime);

            bu_opt->seqno = ntohs(bu_opt->seqno);
            bu_opt->lifetime = ntohl(bu_opt->lifetime);

            /* Set the BU option present flag */
            mip6_inp->optflag |= MIP6_DSTOPT_BU;

            /* If sub-options are present, store them as well. */
            if (bu_opt->len > IP6OPT_BULEN) {
                totlen = bu_opt->len + 2;
                error = mip6_store_dstsubopt(mp, opt, optoff, totlen, tmplen);
                if (error)
                    return error;
            }
            break;
        case IP6OPT_BINDING_ACK:
            /* Allocate and store all Binding Acknowledgement option data */
            mip6_inp->ba_opt = (struct mip6_opt_ba *)
                MALLOC(sizeof(struct mip6_opt_ba), M_TEMP, M_WAITOK);
            if (mip6_inp->ba_opt == NULL)
                return ENOBUFS;
            bzero(mip6_inp->ba_opt, sizeof(struct mip6_opt_ba));

            ba_opt = mip6_inp->ba_opt;
	    m_copydata(mp, optoff, sizeof(ba_opt->type),
		(caddr_t)&ba_opt->type);
            tmplen = sizeof(ba_opt->type);
	    m_copydata(mp, optoff + tmplen, sizeof(ba_opt->len),
                (caddr_t)&ba_opt->len);
            tmplen += sizeof(ba_opt->len);
	    m_copydata(mp, optoff + tmplen, sizeof(ba_opt->status),
		(caddr_t)&ba_opt->status);
            tmplen += sizeof(ba_opt->status);
	    m_copydata(mp, optoff + tmplen, sizeof(ba_opt->seqno),
		(caddr_t)&ba_opt->seqno);
            tmplen += sizeof(ba_opt->seqno);
	    m_copydata(mp, optoff + tmplen, sizeof(ba_opt->lifetime),
                (caddr_t)&ba_opt->lifetime);
            tmplen += sizeof(ba_opt->lifetime);
	    m_copydata(mp, optoff + tmplen, sizeof(ba_opt->refresh),
                  (caddr_t)&ba_opt->refresh);
            tmplen += sizeof(ba_opt->refresh);

            ba_opt->seqno = ntohs(ba_opt->seqno);
            ba_opt->lifetime = ntohl(ba_opt->lifetime);
            ba_opt->refresh = ntohl(ba_opt->refresh);

            /* Set the BA option present flag */
            mip6_inp->optflag |= MIP6_DSTOPT_BA;

            /* If sub-options are present, store them as well */
            if (ba_opt->len > IP6OPT_BALEN) {
                totlen = ba_opt->len + 2;
                error = mip6_store_dstsubopt(mp, opt, optoff, totlen, tmplen);
                if (error)
                    return error;
            }
            break;
        case IP6OPT_BINDING_REQ:
            /* Allocate and store Binding Update option data */
            mip6_inp->br_opt = (struct mip6_opt_br *)
                MALLOC(sizeof(struct mip6_opt_br), M_TEMP, M_WAITOK);
            if (mip6_inp->br_opt == NULL)
                return ENOBUFS;
            bzero(mip6_inp->br_opt, sizeof(struct mip6_opt_br));

            br_opt = mip6_inp->br_opt;
	    m_copydata(mp, optoff, sizeof(br_opt->type),
                (caddr_t)&br_opt->type);
            tmplen = sizeof(br_opt->type);
	    m_copydata(mp, optoff + tmplen, sizeof(br_opt->len),
		(caddr_t)&br_opt->len);
            tmplen += sizeof(br_opt->len);

            /* Set the BR option present flag */
            mip6_inp->optflag |= MIP6_DSTOPT_BR;

            /* If sub-options are present, store them as well. */
            if (br_opt->len > IP6OPT_BRLEN) {
                totlen = br_opt->len + 2;
                error = mip6_store_dstsubopt(mp, opt, optoff, totlen, tmplen);
                if (error)
                    return error;
            }
            break;
        case IP6OPT_HOME_ADDRESS:
            /* Allocate and store Home Address option data */
            mip6_inp->ha_opt = (struct mip6_opt_ha *)
                MALLOC(sizeof(struct mip6_opt_ha), M_TEMP, M_WAITOK);
            if (mip6_inp->ha_opt == NULL)
                return ENOBUFS;
            bzero(mip6_inp->ha_opt, sizeof(struct mip6_opt_ha));

            /* Store Home Address option data */
            ha_opt = mip6_inp->ha_opt;
	    m_copydata(mp, optoff, sizeof(ha_opt->type),
                (caddr_t)&ha_opt->type);
            tmplen = sizeof(ha_opt->type);
	    m_copydata(mp, optoff + tmplen, sizeof(ha_opt->len),
                (caddr_t)&ha_opt->len);
            tmplen += sizeof(ha_opt->len);
	    m_copydata(mp, optoff + tmplen, sizeof(ha_opt->home_addr),
		(caddr_t)&ha_opt->home_addr);
            tmplen += sizeof(ha_opt->home_addr);

            /* Set the HA option present flag */
            mip6_inp->optflag |= MIP6_DSTOPT_HA;
            break;
        default:
            /* We will not come here since the calling function knows
               which options to call this function for. */
    }
    return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_store_dstsubopt
 * Description: Save each MIPv6 suboption from the Destination header.
 *              They will be evaluated when the entire destination header has
 *              been read.
 * Ret value:   0 if OK
 *              Otherwise protocol error code from netinet/in.h
 ******************************************************************************
 */
int
mip6_store_dstsubopt(mp, opt, optoff, totlen, tmplen)
struct mbuf *mp;      /* Pointer to start of mbuf */
u_int8_t    *opt;     /* Pointer to start of current option in mbuf */
u_int8_t     optoff;  /* Offset from start of mbuf to current option */
int          totlen;  /* Total length for option + sub-options */
int          tmplen;  /* Tmp length for positioning in option */
{
    struct mip6_subopt_hal *hal;
    struct mip6_subopt_coa *coa;
    int                     ii, len;

    /* Loop over the sub-options. */
    while (tmplen < totlen) {
        switch (*(opt + tmplen)) {
            case IP6OPT_PAD1:
                tmplen += 1;
                break;
            case IP6OPT_PADN:
                tmplen += *(opt + tmplen + 1) + 2;
                break;
            case IP6SUBOPT_UNIQUEID:
                /* Make sure that the length is OK */
                if (*(opt + tmplen + 1) != IP6OPT_UIDLEN) {
                    MIP6_FREEINDATA;
                    return EIO;
                }

                /* Allocate and store additional sub-option data */
                mip6_inp->uid = (struct mip6_subopt_id *)
                    MALLOC(sizeof(struct mip6_subopt_id), M_TEMP, M_WAITOK);
                if (mip6_inp->uid == NULL)
                    return ENOBUFS;
                bzero(mip6_inp->uid, sizeof(struct mip6_subopt_id));

		m_copydata(mp, optoff + tmplen, sizeof(struct mip6_subopt_id),
                    (caddr_t)mip6_inp->uid);
                tmplen += sizeof(struct mip6_subopt_id);
                mip6_inp->uid->id = ntohs(mip6_inp->uid->id);

                /* Set the Unique Id sub-option present flag */
                mip6_inp->optflag |= MIP6_DSTOPT_UID;
                break;
            case IP6SUBOPT_HALIST:
                /* Make sure that the length is OK */
                if (*(opt + tmplen + 1) % IP6OPT_HALISTLEN) {
                    MIP6_FREEINDATA;
                    return EIO;
                }

                /* Allocate and store additional sub-option data */
                len = *(opt + tmplen +1) / IP6OPT_HALISTLEN;
                mip6_inp->hal = (struct mip6_subopt_hal *)
                    MALLOC(sizeof(struct mip6_subopt_hal) +
                           (len - 1) * sizeof(struct in6_addr),
                           M_TEMP, M_WAITOK);
                if (mip6_inp->hal == NULL) {
                    MIP6_FREEINDATA;
                    return ENOMEM;
                }

                hal = mip6_inp->hal;
		m_copydata(mp, optoff + tmplen, sizeof(hal->type),
                    (caddr_t)&hal->type);
                tmplen += sizeof(hal->type);
		m_copydata(mp, optoff + tmplen, sizeof(hal->len),
                    (caddr_t)&hal->len);
                tmplen += sizeof(hal->len);

                /* Loop over the addresses */
                for (ii = 0; ii < len; ii++) {
		    m_copydata(mp, optoff, tmplen, (caddr_t)&hal->halist[ii]);
                    tmplen += sizeof(struct in6_addr);
                }

                /* Set the BA HA List sub-option present flag */
                mip6_inp->optflag |= MIP6_DSTOPT_HAL;
                break;
            case IP6SUBOPT_ALTCOA:
                /* Make sure that the length is OK */
                if (*(opt + tmplen + 1) != IP6OPT_COALEN) {
                    MIP6_FREEINDATA;
                    return EIO;
                }

                /* Allocate and store additional sub-option data */
                mip6_inp->coa = (struct mip6_subopt_coa *)
                    MALLOC(sizeof(struct mip6_subopt_coa), M_TEMP, M_WAITOK);
                if (mip6_inp->coa == NULL)
                    return ENOBUFS;
                bzero(mip6_inp->coa, sizeof(struct mip6_subopt_coa));

                coa = mip6_inp->coa;
		m_copydata(mp, optoff + tmplen, sizeof(coa->type),
                    (caddr_t)&coa->type);
                tmplen += sizeof(coa->type);
		m_copydata(mp, optoff + tmplen, sizeof(coa->len),
                    (caddr_t)&coa->len);
                tmplen += sizeof(coa->len);
		m_copydata(mp, optoff + tmplen, sizeof(coa->coa),
                    (caddr_t)&coa->coa);
                tmplen += sizeof(coa->coa);

                /* Set the Alternate COA sub-option present flag */
                mip6_inp->optflag |= MIP6_DSTOPT_COA;
                break;
            default:
                /* Quietly ignore and skip over the sub-option.
                   No statistics done. */
                tmplen += *(opt + tmplen + 1) + 2;
        }
    }
    return 0;
}



/*
 ##############################################################################
 #
 # SENDING FUNCTIONS
 # Functions used for processing of the outgoing IPv6 packet.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_output
 * Description: This function is always called by function ip6_output. If there
 *              are any Destination Header options they will be added. A Home
 *              Address option MUST be added if the MN is roaming. Otherwise
 *              nothing is done.
 *              The options are stored in an output queue as a chain of mbufs
 *              associated with a destination address. This approach makes it
 *              possible to send it in any IPv6 packet carrying any payload,
 *              i.e piggy backing.
 * Ret value:   0 if OK
 *              Otherwise any appropriate error code
 ******************************************************************************
 */
int
mip6_output(m, pktopt)
struct mbuf          *m;       /* Includes IPv6 header */
struct ip6_pktopts  **pktopt;  /* Packet Extension headers, options and data */
{
    struct ip6_pktopts  *opt;      /* Packet Extension headers (local) */
    struct mip6_output  *outp;     /* Ptr to mip6 output element */
    struct mip6_esm     *esp;      /* Ptr to entry in event state list */
    struct ip6_hdr      *ip6;      /* IPv6 header */
    struct mip6_bc      *bcp;      /* Binding Cache list entry */
    struct mip6_bul     *bulp;
    struct mip6_bul     *bulp_hr;
    struct in6_addr     *dst_addr; /* Original dst address for the packet */
    int       error;    /* Error code from function call */
    int       off;      /* Offset from start of Destination Header in bytes */
    u_int8_t  opttype;  /* Option type */

    ip6 = mtod(m, struct ip6_hdr *);
    opt = *pktopt;

    /* We have to maintain a list of all prefixes announced by the
       rtadvd deamon (for on-link determination). */
    if (MIP6_IS_HA_ACTIVE) {
        if (ip6->ip6_nxt == IPPROTO_ICMPV6)
            if (mip6_icmp6_output_hook) (*mip6_icmp6_output_hook)(m);
    }

    /* If a COA for the destination address exist, i.e a BC entry is found,
       then add a Routing Header and change the destination address to the
       MN's COA. */
    dst_addr = &ip6->ip6_dst;
    bcp = mip6_bc_find(&ip6->ip6_dst);
    if (bcp != NULL) {
        dst_addr = &bcp->home_addr;
        if ((error = mip6_add_rh(&opt, bcp)) != 0)
            return error;
    }

    /* If this is a MN and the source address is one of the home addresses
       for the MN then a Home Address option must be inserted. */
    esp = NULL;
    if (MIP6_IS_MN_ACTIVE) {
        if (mip6_esm_find_hook)
            esp = (*mip6_esm_find_hook)(&ip6->ip6_src);
	
        if ((esp != NULL) && (esp->state >= MIP6_STATE_DEREG)) {
            if (opt == NULL) {
                opt = (struct ip6_pktopts *)
                    MALLOC(sizeof(struct ip6_pktopts), M_TEMP, M_WAITOK);
                if (opt == NULL)
                    return ENOBUFS;
                bzero(opt, sizeof(struct ip6_pktopts));
                opt->ip6po_hlim = -1;  /* -1 means to use default hop limit */
            }

            mip6_dest_offset(opt->ip6po_dest2, &off);
            if ((error = mip6_add_ha(&opt->ip6po_dest2,
                                     &off, &ip6->ip6_src, &esp->coa)) != 0)
                return error;

	    /* If the MN initiate the traffic it should add a BU option
	       to the packet if no BUL entry exist and there is a BUL
	       "home registration" entry. */
	    bulp = mip6_bul_find(dst_addr, &esp->home_addr);
	    bulp_hr = mip6_bul_find(NULL, &esp->home_addr);
	    if ((bulp == NULL) && (bulp_hr != NULL)) {
		    /* Create BUL entry and BU option. */
		    bulp = mip6_bul_create(dst_addr, &esp->home_addr,
					   &esp->coa,
					   bulp_hr->lifetime, 0);
		    if (bulp == NULL)
			    return ENOBUFS;
		    mip6_queue_bu(bulp, &esp->home_addr, &esp->coa, 0,
				  bulp_hr->lifetime);
	    }
        }
    }

    /* BU, BR and BA should not be sent to link-local, loop-back and
       multicast addresses. */
    if (IN6_IS_ADDR_LINKLOCAL(dst_addr) || IN6_IS_ADDR_LOOPBACK(dst_addr) ||
        IN6_IS_ADDR_MULTICAST(dst_addr)) {
        *pktopt = opt;
        return 0;
    }

    /* If the packet has not been generated completely by MIP6 the
       output queue is searched. */
    outp = NULL;
    if (mip6_config.enable_outq) {
        for (outp = mip6_outq; outp; outp = outp->next) {
            if ((outp->flag == NOT_SENT) &&
                (IN6_ARE_ADDR_EQUAL(&outp->ip6_dst, dst_addr)))
                break;
        }
    }
    if (outp == NULL) {
        *pktopt = opt;
        return 0;
    }

    /* Destination option (either BU, BR or BA) found in the output list.
       Add it to the existing destination options. */
    if (opt == NULL) {
        opt = (struct ip6_pktopts *)MALLOC(sizeof(struct ip6_pktopts),
                                           M_TEMP, M_WAITOK);
        if (opt == NULL)
            return ENOBUFS;
        bzero(opt, sizeof(struct ip6_pktopts));
        opt->ip6po_hlim = -1;  /* -1 means to use default hop limit */
    }

    mip6_dest_offset(opt->ip6po_dest2, &off);
    bcopy((caddr_t)outp->opt, (caddr_t)&opttype, 1);
    if (opttype == IP6OPT_BINDING_UPDATE) {
        /* Add my Binding Update option to the Destination Header */
        error = mip6_add_bu(&opt->ip6po_dest2, &off,
                            (struct mip6_opt_bu *)outp->opt,
                            (struct mip6_subbuf *)outp->subopt);
        if (error)
            return error;
    } else if (opttype == IP6OPT_BINDING_ACK) {
        /* Add my BA option to the Destination Header */
        error = mip6_add_ba(&opt->ip6po_dest2, &off,
                            (struct mip6_opt_ba *)outp->opt,
                            (struct mip6_subbuf *)outp->subopt);
        if (error)
            return error;
    } else if (opttype == IP6OPT_BINDING_REQ) {
        /* Add my BR option to the Destination Header */
        error = mip6_add_br(&opt->ip6po_dest2, &off,
                            (struct mip6_opt_br *)outp->opt,
                            (struct mip6_subbuf *)outp->subopt);
        if (error)
            return error;
    }

    /* Set flag for entry in output queueu to indicate that it has
       been sent. */
    outp->flag = SENT;
    *pktopt = opt;
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
 * Function:    mip6_add_rh
 * Description: Add a Routing Header type 0 to the outgoing packet, if its not
 *              already present, and add the COA for the MN.
 *              If a Routing Header type 0 exist, but contains no data, or the
 *              COA for the MN is missing it is added to the Routing Header.
 *              If the Routing Header is not of type 0 the function returns.
 * Ret value:   0       OK. Routing Header might have been added
 *              ENOBUFS No memory available
 * Note:        The destination address for the outgoing packet is not changed
 *              since this is taken care of in the ip6_output function.
 ******************************************************************************
 */
int
mip6_add_rh(opt, bcp)
struct ip6_pktopts  **opt;  /* Packet Ext headers, options and data */
struct mip6_bc       *bcp;  /* Binding Cache list entry */
{
    struct ip6_pktopts *opt_local;  /* Pkt Ext headers, options & data */
    struct ip6_rthdr0  *rthdr0;     /* Routing header type 0 */
    struct in6_addr    *ip6rt_addr; /* IPv6 routing address(es) */
    caddr_t             ptr;        /* Temporary pointer */
    int                 ii, len, new_len, idx;

    /* A Multicast address must not appear in a Routing Header. */
    if (IN6_IS_ADDR_MULTICAST(&bcp->coa))
        return 0;

    opt_local = *opt;
    if (opt_local == NULL) {
        /* No Packet options present at all. Add a Routing Header. */
        opt_local = (struct ip6_pktopts *)MALLOC(sizeof(struct ip6_pktopts),
                                                 M_TEMP, M_WAITOK);
        if (opt_local == NULL)
            return ENOBUFS;
        bzero(opt_local, sizeof(struct ip6_pktopts));
        opt_local->ip6po_hlim = -1;  /* -1 means to use default hop limit */

        opt_local->ip6po_rhinfo.ip6po_rhi_rthdr =
            mip6_create_rh(&bcp->coa, IPPROTO_IP);
        if(opt_local->ip6po_rhinfo.ip6po_rhi_rthdr == NULL)
            return ENOBUFS;
    } else if (opt_local->ip6po_rhinfo.ip6po_rhi_rthdr == NULL) {
        /* Packet extension header allocated but no RH present, add one. */
        opt_local->ip6po_rhinfo.ip6po_rhi_rthdr =
            mip6_create_rh(&bcp->coa, IPPROTO_IP);
        if(opt_local->ip6po_rhinfo.ip6po_rhi_rthdr == NULL)
            return ENOBUFS;
    } else {
        /* A RH exist. Don't do anything if the type is not 0. */
        if (opt_local->ip6po_rhinfo.ip6po_rhi_rthdr->ip6r_type !=
            IPV6_RTHDR_TYPE_0)
            return 0;

        /* If the outgoing packet contains a BA the Routing Header is
           correct generated by MIP6. No further action is needed. */
        if (opt_local->ip6po_dest2 == NULL)
            return 0;

        len = (opt_local->ip6po_dest2->ip6d_len + 1) << 3;
        ii = 2;
        ptr = (caddr_t)opt_local->ip6po_dest2 + 2;
        while (ii < len) {
            if (*ptr == IP6OPT_PAD1) {
                ii += 1;
                ptr += 1;
                continue;
            }
            if (*ptr == IP6OPT_BINDING_ACK)
                return 0;
            ii += *(ptr + 1) + 2;
            ptr += *(ptr + 1) + 2;
        }

        /* A routing header exist and the outgoing packet does not include
           a BA. The routing header has been generated by a user and must
           be checked. If the last segment is not equal to the MN's COA,
           add it. */
        len = opt_local->ip6po_rhinfo.ip6po_rhi_rthdr->ip6r_len;
        if (len == 0)
            new_len = 2;
        else {
            new_len = len + 2;
            idx = (len / 2) - 1;
            rthdr0 = (struct ip6_rthdr0 *)
                opt_local->ip6po_rhinfo.ip6po_rhi_rthdr;
            ptr = (caddr_t)rthdr0 + sizeof(struct ip6_rthdr0);
            ip6rt_addr = (struct in6_addr *)ptr;
            if (IN6_ARE_ADDR_EQUAL(&bcp->coa, ip6rt_addr + idx))
                return 0;
        }

        rthdr0 = (struct ip6_rthdr0 *)
            MALLOC(sizeof(struct ip6_rthdr0) +
                   (new_len / 2) * sizeof(struct in6_addr), M_TEMP, M_WAITOK);
        if (rthdr0 == NULL)
            return ENOBUFS;

        bcopy((caddr_t)opt_local->ip6po_rhinfo.ip6po_rhi_rthdr,
              (caddr_t)rthdr0, (len + 1) * 8);
        bcopy((caddr_t)&bcp->coa, (caddr_t)rthdr0 + (len + 1) * 8,
              sizeof(struct in6_addr));
        rthdr0->ip6r0_len = new_len;
        rthdr0->ip6r0_segleft = new_len / 2;

        FREE(opt_local->ip6po_rhinfo.ip6po_rhi_rthdr, M_IP6OPT);
        opt_local->ip6po_rhinfo.ip6po_rhi_rthdr =
            (struct ip6_rthdr *)rthdr0;
    }

    /* Change the IP destination address to the COA for the MN. */
    *opt = opt_local;
    return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_align
 * Description: Align the outgoing Destination Header to 8-byte
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_align(dstopt, off)
struct ip6_dest *dstopt;  /* IPv6 destination options for the packet */
int             *off;     /* Offset from start of Destination Header (byte) */
{
    int       rest;     /* Rest of modulo division */
    u_int8_t  padlen;   /* Number of bytes to pad */
    u_int8_t  padn;     /* Number for option type PADN */

    padn = IP6OPT_PADN;
    rest = *off % 8;
    if (rest) {
        padlen = 8 - rest;
        if (rest == 7) {
            /* Add a PAD1 option */
            bzero((caddr_t)dstopt + *off, 1);
            *off += 1;
        } else  {
            /* Add a PADN option */
            bzero((caddr_t)dstopt + *off, padlen);
            bcopy(&padn, (caddr_t)dstopt + *off, 1);
            padlen = padlen - 2;
            bcopy(&padlen, (caddr_t)dstopt + *off + 1, 1);
            *off += padlen + 2;
        }
    }
}



/*
 ******************************************************************************
 * Function:    mip6_dest_offset
 * Description: Calculate offset for new data in the Destination Header.
 *              Additional options will be added beginning at the offset.
 ******************************************************************************
 */
void
mip6_dest_offset(dstopt, off)
struct ip6_dest *dstopt;  /* IPv6 destination options for the packet */
int             *off;     /* Offset from start of Destination Header (byte) */
{
    int         ii;       /* Internal counter */
    u_int8_t    opttype;  /* Option type found in Destination Header*/
    u_int8_t    optlen;   /* Option length incl type and length */
    u_int32_t   len;      /* Length of Destination Header in bytes */

    if (dstopt == NULL) {
        *off = 0;
        return;
    }

    len = (dstopt->ip6d_len + 1) << 3;
    *off = 2;

    for (ii = 2; ii < len;) {
        bcopy((caddr_t)dstopt + ii, (caddr_t)&opttype, 1);
        if (opttype == IP6OPT_PAD1) {
            *off = ii;
            ii += 1;
            continue;
        }
        bcopy((caddr_t)dstopt + ii + 1, (caddr_t)&optlen, 1);
        if (opttype == IP6OPT_PADN) {
            *off = ii;
            ii += 2 + optlen;
        } else {
            ii += 2 + optlen;
            *off = ii;
        }
    }
}



/*
 ******************************************************************************
 * Function:    mip6_add_ha
 * Description: Add Home Address option to the Destination Header. Change the
 *              IPv6 source address to the care-of address of the MN.
 * Ret value:   0 if OK
 *              Otherwise any appropriate error code
 ******************************************************************************
 */
int
mip6_add_ha(dstopt, off, src_addr, coa)
struct ip6_dest **dstopt;   /* IPv6 destination options for the packet */
int             *off;       /* Offset from start of Dest Header (byte) */
struct in6_addr *src_addr;  /* IPv6 header source address */
struct in6_addr *coa;       /* MN's care-of address */
{
    struct ip6_dest *new_opt;  /* Old dest options + Home address option */
    struct ip6_dest *dest;     /* Local variable for destination option */
    int             ii;        /* Internal counter */
    int             rest;      /* Rest of modulo division */
    u_int8_t        padn;      /* Number for option type PADN */
    u_int8_t        opttype;   /* Option type */
    u_int8_t        optlen;    /* Option length excluding type and length */
    u_int8_t        dstlen;    /* destination Header length in 8-bytes */
    u_int32_t       len;       /* Length of Destination Header in bytes */

    /* Allocate memory for the Home Address option */
    dest = *dstopt;
    if (dest == NULL) {
        dest = (struct ip6_dest *)MALLOC(sizeof(struct ip6_dest) +
                                         sizeof(struct mip6_opt_ha),
                                         M_TEMP, M_WAITOK);
        if (dest == NULL)
            return ENOBUFS;
        bzero(dest, sizeof(struct ip6_dest) + sizeof(struct mip6_opt_ha));
        *off = 2;
    } else {
        len = (dest->ip6d_len + 1) << 3;
        new_opt = (struct ip6_dest *)MALLOC(len +
                                            sizeof(struct mip6_opt_ha),
                                            M_TEMP, M_WAITOK);
        if (new_opt == NULL)
            return ENOBUFS;
        bzero(new_opt, len + sizeof(struct mip6_opt_ha));
        bcopy((caddr_t)dest, (caddr_t)new_opt, len);
        FREE(dest, M_IP6OPT);
        dest = new_opt;
    }

    /* Make sure that the offset is correct for adding a Home Address
       option */
    padn = IP6OPT_PADN;
    rest = *off % 4;
    if (rest == 0) {
        /* Add a PADN option with length 0 */
        bzero((caddr_t)dest + *off, 2);
        bcopy(&padn, (caddr_t)dest + *off, 1);
        *off += 2;
    } else if (rest == 1) {
        /* Add a PAD1 option */
        bzero((caddr_t)dest + *off, 1);
        *off += 1;
    } else if (rest == 3) {
        /* Add a PADN option with length 1 */
        bzero((caddr_t)dest + *off, 3);
        bcopy(&padn, (caddr_t)dest + *off, 1);
        bcopy(&padn, (caddr_t)dest + *off + 1, 1);
        *off += 3;
    }

    /* Add the options in the way they shall be added. */
    opttype = IP6OPT_HOME_ADDRESS;
    optlen = IP6OPT_HALEN;

    bcopy(&opttype, (caddr_t)dest + *off, 1);
    *off += 1;
    bcopy(&optlen, (caddr_t)dest + *off, 1);
    *off += 1;

    for (ii = 0; ii < 4; ii++) {
        bcopy((caddr_t)&src_addr->s6_addr32[ii], (caddr_t)dest + *off, 4);
        *off += 4;
    }

    /* Align the Destination Header to 8-byte */
    mip6_align(dest, off);

    /* Change the total length of the Destination header */
    dstlen = (*off >> 3) - 1;
    bcopy(&dstlen, (caddr_t)dest + 1, 1);

    /* Change the IP6 source address to the care-of address */
    src_addr->s6_addr32[0] = coa->s6_addr32[0];
    src_addr->s6_addr32[1] = coa->s6_addr32[1];
    src_addr->s6_addr32[2] = coa->s6_addr32[2];
    src_addr->s6_addr32[3] = coa->s6_addr32[3];
    *dstopt = dest;
    return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_add_bu
 * Description: Copy BU option and sub-option (if present) to a Destination
 *              Header.
 *              Memory in the Destination Header for the BU is created, the
 *              header is aligned to 8-byte alignment and the total length of
 *              the header is updated.
 * Ret value:   0 if OK
 *              Otherwise any appropriate error code
 ******************************************************************************
 */
int
mip6_add_bu(dstopt, off, optbu, subopt)
struct ip6_dest    **dstopt;  /* IPv6 destination options for the packet */
int                 *off;     /* Offset from start of Dest Header (byte) */
struct mip6_opt_bu  *optbu;   /* BU option data */
struct mip6_subbuf  *subopt;  /* BU sub-option data (NULL if not present) */
{
    struct ip6_dest *new_opt;  /* Old destination options + BU option */
    struct ip6_dest *dest;     /* Local variable for destination option */
    u_int8_t         padn;     /* Number for option type PADN */
    u_int8_t         dstlen;   /* Destination Header length in 8-bytes */
    int              offlen;   /* Offset for option length in the buffer */
    int              rest;     /* Rest of modulo division */
    int              optlen;   /* Length of BU option incl sub-options */
    int              tmp16;    /* Temporary converting of 2-byte */
    int              tmp32;    /* Temporary converting of 4-byte */
    int              len;      /* Length of allocated memory */
    int after, before;

    /* Verify input */
    if (optbu == NULL)
        return 0;

    /* Allocate memory for the BU option and sub-option (if present). */
    dest = *dstopt;
    if (dest == NULL) {
        len = sizeof(struct ip6_dest) + sizeof(struct mip6_opt_bu) + 8;
        if (subopt != NULL)
            len += subopt->len;

        dest = (struct ip6_dest *)MALLOC(len, M_TEMP, M_WAITOK);
        if (dest == NULL)
            return ENOBUFS;
        bzero(dest, len);
        *off = 2;
    } else {
        len = (dest->ip6d_len + 1) << 3;
        len += sizeof(struct mip6_opt_bu) + 8;
        if (subopt != NULL)
            len += subopt->len;

        new_opt = (struct ip6_dest *)MALLOC(len, M_TEMP, M_WAITOK);
        if (new_opt == NULL)
            return ENOBUFS;

        bzero(new_opt, len);
        bcopy((caddr_t)dest, (caddr_t)new_opt, (dest->ip6d_len + 1) << 3);
        FREE(dest, M_IP6OPT);
        dest = new_opt;
    }

    /* Compensate for the alignment requirement. */
    padn = IP6OPT_PADN;
    rest = *off % 4;
    if (rest == 0) {
        /* Add a PADN option with length 0 */
        bzero((caddr_t)dest + *off, 2);
        bcopy(&padn, (caddr_t)dest + *off, 1);
        *off += 2;
    } else if (rest == 1) {
        /* Add a PAD1 option */
        bzero((caddr_t)dest + *off, 1);
        *off += 1;
    } else if (rest == 3) {
        /* Add a PADN option with length 1 */
        bzero((caddr_t)dest + *off, 3);
        bcopy(&padn, (caddr_t)dest + *off, 1);
        bcopy(&padn, (caddr_t)dest + *off + 1, 1);
        *off += 3;
    }
    offlen = *off + 1;

    /* Reset BU option length in case of retransmission. */
    optbu->len = IP6OPT_BULEN;

    /* Copy the BU data from the internal structure to the Dest Header */
    bcopy((caddr_t)&optbu->type, (caddr_t)dest + *off, sizeof(optbu->type));
    *off += sizeof(optbu->type);
    bcopy((caddr_t)&optbu->len, (caddr_t)dest + *off, sizeof(optbu->len));
    *off += sizeof(optbu->len);
    bcopy((caddr_t)&optbu->flags, (caddr_t)dest + *off, sizeof(optbu->flags));
    *off += sizeof(optbu->flags);
    bcopy((caddr_t)&optbu->prefix_len, (caddr_t)dest + *off,
          sizeof(optbu->prefix_len));
    *off += sizeof(optbu->prefix_len);
    tmp16 =  htons(optbu->seqno);
    bcopy((caddr_t)&tmp16, (caddr_t)dest + *off, sizeof(optbu->seqno));
    *off += sizeof(optbu->seqno);
    tmp32 = htonl(optbu->lifetime);
    bcopy((caddr_t)&tmp32, (caddr_t)dest + *off, sizeof(optbu->lifetime));
    *off += sizeof(optbu->lifetime);

    /* If sub-options are present, add them as well. */
    optlen = optbu->len;
    if (subopt) {
	/* Align the Destination Header to 8-byte before sub-options
	   are added. */
	before = *off;
	mip6_align(dest, off);
	after = *off;
	optlen += after - before;
	
        bcopy((caddr_t)subopt->buffer, (caddr_t)dest + *off, subopt->len);
        *off += subopt->len;
        optlen += subopt->len;
        optbu->len += subopt->len;
    }

    /* Make sure that the option length is correct. */
    bcopy((caddr_t)&optlen, (caddr_t)dest + offlen, 1);

    /* Align the Destination Header to 8-byte */
    mip6_align(dest, off);

    /* Change the total length of the Destination header */
    dstlen = (*off >> 3) - 1;
    bcopy(&dstlen, (caddr_t)dest + 1, 1);
    *dstopt = dest;
    return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_add_ba
 * Description: Copy BA option and sub-option (if present) to a Destination
 *              Header.
 *              Memory in the Destination Header for the BU is created, the
 *              header is aligned to 8-byte alignment and the total length of
 *              the header is updated.
 * Ret value:   0 if OK
 *              Otherwise any appropriate error code
 ******************************************************************************
 */
int
mip6_add_ba(dstopt, off, optba, subopt)
struct ip6_dest     **dstopt;  /* IPv6 dest options for the packet */
int                 *off;      /* Offset from start of dest Header (byte) */
struct mip6_opt_ba  *optba;    /* BA option data */
struct mip6_subbuf  *subopt;   /* BA sub-option data (NULL if not present) */
{
    struct ip6_dest *new_opt;   /* Old destination options + BA option */
    struct ip6_dest *dest;      /* Local variable for destination option */
    u_int8_t        padn;       /* Number for option type PADN */
    u_int8_t        dstlen;     /* Destination Header length in 8-bytes */
    int             offlen;     /* Offset for option length in the buffer */
    int             optlen;     /* Length of BA option incl sub-options */
    int             rest;       /* Rest of modulo division */
    int             tmp16;      /* Temporary converting of 2-byte */
    int             tmp32;      /* Temporary converting of 4-byte */
    int             len;        /* Length of allocated memory */
    int after, before;

    /* Verify input */
    if (optba == NULL)
        return 0;

    /* Allocate memory for the BA option and sub-option (if present). */
    dest = *dstopt;
    if (dest == NULL) {
        len = sizeof(struct ip6_dest) + sizeof(struct mip6_opt_ba) + 8;
        if (subopt != NULL)
            len += subopt->len;

        dest = (struct ip6_dest *)MALLOC(len, M_TEMP, M_WAITOK);
        if (dest == NULL)
            return ENOBUFS;
        bzero(dest, len);
        *off = 2;
    } else {
        len = (dest->ip6d_len + 1) << 3;
        len += sizeof(struct mip6_opt_ba) + 8;
        if (subopt != NULL)
            len += subopt->len;

        new_opt = (struct ip6_dest *)MALLOC(len, M_TEMP, M_WAITOK);
        if (new_opt == NULL)
            return ENOBUFS;
        bzero(new_opt, len);
        bcopy((caddr_t)dest, (caddr_t)new_opt, (dest->ip6d_len + 1) << 3);
        FREE(dest, M_IP6OPT);
        dest = new_opt;
    }

    /* Compensate for the alignment requirement. */
    padn = IP6OPT_PADN;
    rest = *off % 4;
    if (rest == 1) {
        /* Add a PADN option with length 0 */
        bzero((caddr_t)dest + *off, 2);
        bcopy(&padn, (caddr_t)dest + *off, 1);
        *off += 2;
    } else if (rest == 2) {
        /* Add a PAD1 option */
        bzero((caddr_t)dest + *off, 1);
        *off += 1;
    } else if (rest == 0) {
        /* Add a PADN option with length 1 */
        bzero((caddr_t)dest + *off, 3);
        bcopy(&padn, (caddr_t)dest + *off, 1);
        bcopy(&padn, (caddr_t)dest + *off + 1, 1);
        *off += 3;
    }
    offlen = *off + 1;

    /* Copy the BA data from the internal structure to mbuf */
    bcopy((caddr_t)&optba->type, (caddr_t)dest + *off, sizeof(optba->type));
    *off += sizeof(optba->type);
    bcopy((caddr_t)&optba->len, (caddr_t)dest + *off, sizeof(optba->len));
    *off += sizeof(optba->len);
    bcopy((caddr_t)&optba->status, (caddr_t)dest + *off,
          sizeof(optba->status));
    *off += sizeof(optba->status);
    tmp16 = htons(optba->seqno);
    bcopy((caddr_t)&tmp16, (caddr_t)dest + *off, sizeof(optba->seqno));
    *off += sizeof(optba->seqno);
    tmp32 = htonl(optba->lifetime);
    bcopy((caddr_t)&tmp32, (caddr_t)dest + *off, sizeof(optba->lifetime));
    *off += sizeof(optba->lifetime);
    tmp32 = htonl(optba->refresh);
    bcopy((caddr_t)&tmp32, (caddr_t)dest + *off, sizeof(optba->refresh));
    *off += sizeof(optba->refresh);

    /* If sub-options are present, add them as well. */
    optlen = IP6OPT_BALEN;
    if (subopt) {
	/* Align the Destination Header to 8-byte before sub-options
	   are added. */
	before = *off;
	mip6_align(dest, off);
	after = *off;
	optlen += after - before;
	
        bcopy((caddr_t)subopt->buffer, (caddr_t)dest + *off, subopt->len);
        *off += subopt->len;
        optlen += subopt->len;
        optba->len += subopt->len;
    }

    /* Make sure that the option length is correct. */
    bcopy((caddr_t)&optlen, (caddr_t)dest + offlen, 1);

    /* Align the Destination Header to 8-byte */
    mip6_align(dest, off);

    /* Change the total length of the Destination header */
    dstlen = (*off >> 3) - 1;
    bcopy(&dstlen, (caddr_t)dest + 1, 1);
    *dstopt = dest;
    return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_add_br
 * Description: Copy BR option and sub-option (if present) to a Destination
 *              Header.
 *              Memory in the Destination Header for the BU is created, the
 *              header is aligned to 8-byte alignment and the total length of
 *              the header is updated.
 * Ret value:   0 if OK
 *              Otherwise any appropriate error code
 ******************************************************************************
 */
int
mip6_add_br(dstopt, off, optbr, subopt)
struct ip6_dest     **dstopt;  /* IPv6 destination options for the packet */
int                 *off;      /* Offset from start of Dest Header (byte) */
struct mip6_opt_br  *optbr;    /* BR option data */
struct mip6_subbuf  *subopt;   /* BR sub-option data (NULL if not present) */
{
    struct ip6_dest *new_opt;   /* Old destination options + BU option */
    struct ip6_dest *dest;      /* Local variable for destination option */
    u_int8_t        dstlen;     /* Destination Header length in 8-bytes */
    int             offlen;     /* Offset for option length in the buffer */
    int             rest;       /* Rest of modulo division */
    int             optlen;     /* Length of BR option incl sub-options */
    int             len;        /* Length of allocated memory */
    int after, before;

    /* Verify input */
    if (optbr == NULL)
        return 0;

    /* Allocate memory for the BR option and sub-option (if present). */
    dest = *dstopt;
    if (dest == NULL) {
        len = sizeof(struct ip6_dest) + sizeof(struct mip6_opt_br) + 8;
        if (subopt != NULL)
            len += subopt->len;

        dest = (struct ip6_dest *)MALLOC(len, M_TEMP, M_WAITOK);
        if (dest == NULL)
            return ENOBUFS;

        bzero(dest, len);
        *off = 2;
    } else {
        len = (dest->ip6d_len + 1) << 3;
        len += sizeof(struct mip6_opt_br) + 8;
        if (subopt != NULL)
            len += subopt->len;

        new_opt = (struct ip6_dest *)MALLOC(len, M_TEMP, M_WAITOK);
        if (new_opt == NULL)
            return ENOBUFS;

        bzero(new_opt, len);
        bcopy((caddr_t)dest, (caddr_t)new_opt, (dest->ip6d_len + 1) << 3);
        FREE(dest, M_IP6OPT);
        dest = new_opt;
    }

    /* Compensate for the alignment requirement. */
    rest = *off % 4;
    if ((rest == 1) || (rest == 3)) {
        /* Add a PAD1 option */
        bzero((caddr_t)dest + *off, 1);
        *off += 1;
    }
    offlen = *off +1;

    /* Copy the BR data from the internal structure to mbuf */
    bcopy((caddr_t)&optbr->type, (caddr_t)dest + *off, sizeof(optbr->type));
    *off += sizeof(optbr->type);
    bcopy((caddr_t)&optbr->len, (caddr_t)dest + *off, sizeof(optbr->len));
    *off += sizeof(optbr->len);


    /* If sub-options are present, add them as well. */
    optlen = IP6OPT_BRLEN;
    if (subopt) {
	/* Align the Destination Header to 8-byte before sub-options
	   are added. */
	before = *off;
	mip6_align(dest, off);
	after = *off;
	optlen += after - before;
	
        bcopy((caddr_t)subopt->buffer, (caddr_t)dest + *off, subopt->len);
        *off += subopt->len;
        optlen += subopt->len;
        optbr->len += subopt->len;
    }

    /* Make sure that the option length is correct. */
    bcopy((caddr_t)&optlen, (caddr_t)dest + offlen, 1);

    /* Align the Destination Header to 8-byte */
    mip6_align(dest, off);

    /* Change the total length of the Destination header */
    dstlen = (*off >> 3) - 1;
    bcopy(&dstlen, (caddr_t)dest + 1, 1);
    *dstopt = dest;
    return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_store_subopt
 * Description: Store a sub-option in a buffer. The buffer must be allocated
 *              by the calling function and big enough to hold all the sub-
 *              options that may be added to an option (BU, BR or BA).
 *              Alignement requirement for the different sub-options are taken
 *              care of before its added to the buffer.
 * Ret value:   0 if OK. Otherwise 1
 ******************************************************************************
 */
int
mip6_store_subopt(subbuf, subopt)
struct mip6_subbuf **subbuf;  /* Buffert containing sub-options */
caddr_t              subopt;  /* TLV coded sub-option */
{
    struct mip6_subopt_id  *uid;
    struct mip6_subopt_hal *hal;
    struct mip6_subopt_coa *altcoa;
    struct mip6_subbuf     *buf;
    u_int8_t   pad1, padn;
    u_int16_t  tmp16;
    int        rest, no, ii, padlen;

    /* Make sure that a sub-option is present. */
    if (subopt == NULL)
        return 0;

    /* Allocate memory for buffer if not already allocated. */
    buf = *subbuf;
    if (buf == NULL) {
        buf = (struct mip6_subbuf *)MALLOC(sizeof(struct mip6_subbuf),
                                           M_TEMP, M_WAITOK);
        if (buf == NULL)
            return 1;
        bzero(buf, sizeof(struct mip6_subbuf));
    }

    /* Find offset in the current buffer */
    padn = IP6OPT_PADN;
    pad1 = IP6OPT_PAD1;

    switch (*subopt) {
        case IP6SUBOPT_UNIQUEID:
            /* Make sure that the length is OK */
            uid = (struct mip6_subopt_id *)subopt;
            if (uid->len != IP6OPT_UIDLEN)
                return 1;

            /* Compensate for the alignment requirement. */
            rest =  buf->len % 2;
            if (rest == 1) {
                bcopy(&pad1, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
            }

            /* Copy the sub-option to the buffer. */
            bcopy(&uid->type, (caddr_t)buf->buffer + buf->len,
                  sizeof(uid->type));
            buf->len += sizeof(uid->type);

            bcopy(&uid->len, (caddr_t)buf->buffer + buf->len,
                  sizeof(uid->len));
            buf->len += sizeof(uid->len);

            tmp16 = htons(uid->id);
            bcopy(&tmp16, (caddr_t)buf->buffer + buf->len, sizeof(tmp16));
            buf->len += sizeof(tmp16);
            break;
        case IP6SUBOPT_HALIST:
            /* Make sure that the length is OK */
            hal = (struct mip6_subopt_hal *)subopt;
            if (hal->len % IP6OPT_HALISTLEN)
                return 1;

            /* Compensate for the alignment requirement. */
            rest =  buf->len % 8;
            if (rest > 3) {
                padlen = rest - 4;
                bcopy(&padn, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
                bcopy(&padlen, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
                bzero((caddr_t)buf->buffer + buf->len, padlen);
                buf->len += padlen;
            } else if (rest == 3) {
                bcopy(&pad1, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
            } else if (rest <= 1) {
                padlen = rest + 4;
                bcopy(&padn, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
                bcopy(&padlen, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
                bzero((caddr_t)buf->buffer + buf->len, padlen);
                buf->len += padlen;
            }

            /* Copy the sub-option to the buffer. */
            bcopy(&hal->type, (caddr_t)buf->buffer + buf->len,
                  sizeof(hal->type));
            buf->len += sizeof(hal->type);

            bcopy(&hal->len, (caddr_t)buf->buffer + buf->len,
                  sizeof(hal->len));
            buf->len += sizeof(hal->len);

            /* Loop over the addresses */
            no = hal->len / IP6OPT_HALISTLEN;
            for (ii = 0; ii < no; ii++) {
                bcopy(&hal->halist[ii], (caddr_t)buf->buffer + buf->len,
                      sizeof(hal->halist));
                buf->len += sizeof(hal->halist);
            }
            break;
        case IP6SUBOPT_ALTCOA:
            /* Make sure that the length is OK */
            altcoa = (struct mip6_subopt_coa *)subopt;
            if (altcoa->len % IP6OPT_COALEN)
                return 1;

            /* Compensate for the alignment requirement. */
            rest =  buf->len % 8;
            if (rest > 3) {
                padlen = rest - 4;
                bcopy(&padn, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
                bcopy(&padlen, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
                bzero((caddr_t)buf->buffer + buf->len, padlen);
                buf->len += padlen;
            } else if (rest == 3) {
                bcopy(&pad1, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
            } else if (rest <= 1) {
                padlen = rest + 4;
                bcopy(&padn, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
                bcopy(&padlen, (caddr_t)buf->buffer + buf->len, 1);
                buf->len += 1;
                bzero((caddr_t)buf->buffer + buf->len, padlen);
                buf->len += padlen;
            }

            /* Copy the sub-option to the buffer. */
            bcopy(&altcoa->type, (caddr_t)buf->buffer + buf->len,
                  sizeof(altcoa->type));
            buf->len += sizeof(altcoa->type);

            bcopy(&altcoa->len, (caddr_t)buf->buffer + buf->len,
                  sizeof(altcoa->len));
            buf->len += sizeof(altcoa->len);

            bcopy(&altcoa->coa, (caddr_t)buf->buffer + buf->len,
                  sizeof(altcoa->coa));
            buf->len += sizeof(altcoa->coa);
            break;
        default:
    }
    *subbuf = buf;
    return 0;
}
