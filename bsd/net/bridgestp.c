/*
 * Copyright (c) 2007-2009 Apple Inc. All rights reserved.
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

/*	$fpwf: Revision 1.2  2007/05/17 03:38:46  rnewberry Exp $	*/
/*	$NetBSD: bridgestp.c,v 1.10 2006/11/16 01:33:40 christos Exp $	*/

/*
 * Copyright (c) 2000 Jason L. Wright (jason@thought.net)
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Jason L. Wright
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * OpenBSD: bridgestp.c,v 1.5 2001/03/22 03:48:29 jason Exp
 */

/*
 * Implementation of the spanning tree protocol as defined in
 * ISO/IEC Final DIS 15802-3 (IEEE P802.1D/D17), May 25, 1998.
 * (In English: IEEE 802.1D, Draft 17, 1998)
 */

/*	$NetBSD: if_bridgevar.h,v 1.8 2005/12/10 23:21:38 elad Exp $	*/

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kernel.h>
#include <sys/callout.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_llc.h>

#include <net/if_ether.h>
#include <net/if_bridgevar.h>
#include <net/if_media.h>

#include <net/kpi_interface.h>

/* BPDU message types */
#define	BSTP_MSGTYPE_CFG	0x00		/* Configuration */
#define	BSTP_MSGTYPE_TCN	0x80		/* Topology chg notification */

/* BPDU flags */
#define	BSTP_FLAG_TC		0x01		/* Topology change */
#define	BSTP_FLAG_TCA		0x80		/* Topology change ack */

#define	BSTP_MESSAGE_AGE_INCR	(1 * 256)	/* in 256ths of a second */
#define	BSTP_TICK_VAL		(1 * 256)	/* in 256ths of a second */

/*
 * Because BPDU's do not make nicely aligned structures, two different
 * declarations are used: bstp_?bpdu (wire representation, packed) and
 * bstp_*_unit (internal, nicely aligned version).
 */

/* configuration bridge protocol data unit */
struct bstp_cbpdu {
	uint8_t		cbu_dsap;		/* LLC: destination sap */
	uint8_t		cbu_ssap;		/* LLC: source sap */
	uint8_t		cbu_ctl;		/* LLC: control */
	uint16_t	cbu_protoid;		/* protocol id */
	uint8_t		cbu_protover;		/* protocol version */
	uint8_t		cbu_bpdutype;		/* message type */
	uint8_t		cbu_flags;		/* flags (below) */

	/* root id */
	uint16_t	cbu_rootpri;		/* root priority */
	uint8_t	cbu_rootaddr[6];	/* root address */

	uint32_t	cbu_rootpathcost;	/* root path cost */

	/* bridge id */
	uint16_t	cbu_bridgepri;		/* bridge priority */
	uint8_t		cbu_bridgeaddr[6];	/* bridge address */

	uint16_t	cbu_portid;		/* port id */
	uint16_t	cbu_messageage;		/* current message age */
	uint16_t	cbu_maxage;		/* maximum age */
	uint16_t	cbu_hellotime;		/* hello time */
	uint16_t	cbu_forwarddelay;	/* forwarding delay */
} __attribute__((__packed__));

/* topology change notification bridge protocol data unit */
struct bstp_tbpdu {
	uint8_t		tbu_dsap;		/* LLC: destination sap */
	uint8_t		tbu_ssap;		/* LLC: source sap */
	uint8_t		tbu_ctl;		/* LLC: control */
	uint16_t	tbu_protoid;		/* protocol id */
	uint8_t		tbu_protover;		/* protocol version */
	uint8_t		tbu_bpdutype;		/* message type */
} __attribute__((__packed__));

const uint8_t bstp_etheraddr[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

void	bstp_initialize_port(struct bridge_softc *, struct bridge_iflist *);
void	bstp_ifupdstatus(struct bridge_softc *, struct bridge_iflist *);
void	bstp_enable_port(struct bridge_softc *, struct bridge_iflist *);
void	bstp_disable_port(struct bridge_softc *, struct bridge_iflist *);
void	bstp_enable_change_detection(struct bridge_iflist *);
void	bstp_disable_change_detection(struct bridge_iflist *);
int	bstp_root_bridge(struct bridge_softc *sc);
int	bstp_supersedes_port_info(struct bridge_softc *,
	    struct bridge_iflist *, struct bstp_config_unit *);
int	bstp_designated_port(struct bridge_softc *, struct bridge_iflist *);
int	bstp_designated_for_some_port(struct bridge_softc *);
void	bstp_transmit_config(struct bridge_softc *, struct bridge_iflist *);
void	bstp_transmit_tcn(struct bridge_softc *);
void	bstp_received_config_bpdu(struct bridge_softc *,
	    struct bridge_iflist *, struct bstp_config_unit *);
void	bstp_received_tcn_bpdu(struct bridge_softc *, struct bridge_iflist *,
	    struct bstp_tcn_unit *);
void	bstp_record_config_information(struct bridge_softc *,
	    struct bridge_iflist *, struct bstp_config_unit *);
void	bstp_record_config_timeout_values(struct bridge_softc *,
	    struct bstp_config_unit *);
void	bstp_config_bpdu_generation(struct bridge_softc *);
void	bstp_send_config_bpdu(struct bridge_softc *, struct bridge_iflist *,
	    struct bstp_config_unit *);
void	bstp_configuration_update(struct bridge_softc *);
void	bstp_root_selection(struct bridge_softc *);
void	bstp_designated_port_selection(struct bridge_softc *);
void	bstp_become_designated_port(struct bridge_softc *,
	    struct bridge_iflist *);
void	bstp_port_state_selection(struct bridge_softc *);
void	bstp_make_forwarding(struct bridge_softc *, struct bridge_iflist *);
void	bstp_make_blocking(struct bridge_softc *, struct bridge_iflist *);
void	bstp_set_port_state(struct bridge_iflist *, uint8_t);
void	bstp_set_bridge_priority(struct bridge_softc *, uint64_t);
void	bstp_set_port_priority(struct bridge_softc *, struct bridge_iflist *,
	    uint16_t);
void	bstp_set_path_cost(struct bridge_softc *, struct bridge_iflist *,
	    uint32_t);
void	bstp_topology_change_detection(struct bridge_softc *);
void	bstp_topology_change_acknowledged(struct bridge_softc *);
void	bstp_acknowledge_topology_change(struct bridge_softc *,
	    struct bridge_iflist *);

void	bstp_tick(void *);
void	bstp_timer_start(struct bridge_timer *, uint16_t);
void	bstp_timer_stop(struct bridge_timer *);
int	bstp_timer_expired(struct bridge_timer *, uint16_t);

void	bstp_hold_timer_expiry(struct bridge_softc *, struct bridge_iflist *);
void	bstp_message_age_timer_expiry(struct bridge_softc *,
	    struct bridge_iflist *);
void	bstp_forward_delay_timer_expiry(struct bridge_softc *,
	    struct bridge_iflist *);
void	bstp_topology_change_timer_expiry(struct bridge_softc *);
void	bstp_tcn_timer_expiry(struct bridge_softc *);
void	bstp_hello_timer_expiry(struct bridge_softc *);

void
bstp_transmit_config(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	if (bif->bif_hold_timer.active) {
		bif->bif_config_pending = 1;
		return;
	}

	bif->bif_config_bpdu.cu_message_type = BSTP_MSGTYPE_CFG;
	bif->bif_config_bpdu.cu_rootid = sc->sc_designated_root;
	bif->bif_config_bpdu.cu_root_path_cost = sc->sc_root_path_cost;
	bif->bif_config_bpdu.cu_bridge_id = sc->sc_bridge_id;
	bif->bif_config_bpdu.cu_port_id = bif->bif_port_id;

	if (bstp_root_bridge(sc))
		bif->bif_config_bpdu.cu_message_age = 0;
	else
		bif->bif_config_bpdu.cu_message_age =
		    sc->sc_root_port->bif_message_age_timer.value +
		    BSTP_MESSAGE_AGE_INCR;

	bif->bif_config_bpdu.cu_max_age = sc->sc_max_age;
	bif->bif_config_bpdu.cu_hello_time = sc->sc_hello_time;
	bif->bif_config_bpdu.cu_forward_delay = sc->sc_forward_delay;
	bif->bif_config_bpdu.cu_topology_change_acknowledgment
	    = bif->bif_topology_change_acknowledge;
	bif->bif_config_bpdu.cu_topology_change = sc->sc_topology_change;

	if (bif->bif_config_bpdu.cu_message_age < sc->sc_max_age) {
		bif->bif_topology_change_acknowledge = 0;
		bif->bif_config_pending = 0;
		bstp_send_config_bpdu(sc, bif, &bif->bif_config_bpdu);
		bstp_timer_start(&bif->bif_hold_timer, 0);
	}
}

void
bstp_send_config_bpdu(struct bridge_softc *sc, struct bridge_iflist *bif,
    struct bstp_config_unit *cu)
{
	struct ifnet *ifp;
	struct mbuf *m;
	struct ether_header *eh;
	struct bstp_cbpdu bpdu;

	ifp = bif->bif_ifp;

	if ((ifp->if_flags & IFF_RUNNING) == 0)
		return;

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return;

	eh = mtod(m, struct ether_header *);

	m->m_pkthdr.rcvif = ifp;
	m->m_pkthdr.len = sizeof(*eh) + sizeof(bpdu);
	m->m_len = m->m_pkthdr.len;

	bpdu.cbu_ssap = bpdu.cbu_dsap = LLC_8021D_LSAP;
	bpdu.cbu_ctl = LLC_UI;
	bpdu.cbu_protoid = htons(0);
	bpdu.cbu_protover = 0;
	bpdu.cbu_bpdutype = cu->cu_message_type;
	bpdu.cbu_flags = (cu->cu_topology_change ? BSTP_FLAG_TC : 0) |
	    (cu->cu_topology_change_acknowledgment ? BSTP_FLAG_TCA : 0);

	bpdu.cbu_rootpri = htons(cu->cu_rootid >> 48);
	bpdu.cbu_rootaddr[0] = cu->cu_rootid >> 40;
	bpdu.cbu_rootaddr[1] = cu->cu_rootid >> 32;
	bpdu.cbu_rootaddr[2] = cu->cu_rootid >> 24;
	bpdu.cbu_rootaddr[3] = cu->cu_rootid >> 16;
	bpdu.cbu_rootaddr[4] = cu->cu_rootid >> 8;
	bpdu.cbu_rootaddr[5] = cu->cu_rootid >> 0;

	bpdu.cbu_rootpathcost = htonl(cu->cu_root_path_cost);

	bpdu.cbu_bridgepri = htons(cu->cu_rootid >> 48);
	bpdu.cbu_bridgeaddr[0] = cu->cu_rootid >> 40;
	bpdu.cbu_bridgeaddr[1] = cu->cu_rootid >> 32;
	bpdu.cbu_bridgeaddr[2] = cu->cu_rootid >> 24;
	bpdu.cbu_bridgeaddr[3] = cu->cu_rootid >> 16;
	bpdu.cbu_bridgeaddr[4] = cu->cu_rootid >> 8;
	bpdu.cbu_bridgeaddr[5] = cu->cu_rootid >> 0;

	bpdu.cbu_portid = htons(cu->cu_port_id);
	bpdu.cbu_messageage = htons(cu->cu_message_age);
	bpdu.cbu_maxage = htons(cu->cu_max_age);
	bpdu.cbu_hellotime = htons(cu->cu_hello_time);
	bpdu.cbu_forwarddelay = htons(cu->cu_forward_delay);

	memcpy(eh->ether_shost, ifnet_lladdr(ifp), ETHER_ADDR_LEN);
	memcpy(eh->ether_dhost, bstp_etheraddr, ETHER_ADDR_LEN);
	eh->ether_type = htons(sizeof(bpdu));

	memcpy(mtod(m, caddr_t) + sizeof(*eh), &bpdu, sizeof(bpdu));

	bridge_enqueue(sc, ifp, m); // APPLE MODIFICATION - no flags param
}

int
bstp_root_bridge(struct bridge_softc *sc)
{
	return (sc->sc_designated_root == sc->sc_bridge_id);
}

int
bstp_supersedes_port_info(struct bridge_softc *sc, struct bridge_iflist *bif,
    struct bstp_config_unit *cu)
{
	if (cu->cu_rootid < bif->bif_designated_root)
		return (1);
	if (cu->cu_rootid > bif->bif_designated_root)
		return (0);

	if (cu->cu_root_path_cost < bif->bif_designated_cost)
		return (1);
	if (cu->cu_root_path_cost > bif->bif_designated_cost)
		return (0);

	if (cu->cu_bridge_id < bif->bif_designated_bridge)
		return (1);
	if (cu->cu_bridge_id > bif->bif_designated_bridge)
		return (0);

	if (sc->sc_bridge_id != cu->cu_bridge_id)
		return (1);
	if (cu->cu_port_id <= bif->bif_designated_port)
		return (1);
	return (0);
}

void
bstp_record_config_information(__unused struct bridge_softc *sc,
    struct bridge_iflist *bif, struct bstp_config_unit *cu)
{
	bif->bif_designated_root = cu->cu_rootid;
	bif->bif_designated_cost = cu->cu_root_path_cost;
	bif->bif_designated_bridge = cu->cu_bridge_id;
	bif->bif_designated_port = cu->cu_port_id;
	bstp_timer_start(&bif->bif_message_age_timer, cu->cu_message_age);
}

void
bstp_record_config_timeout_values(struct bridge_softc *sc,
    struct bstp_config_unit *config)
{
	sc->sc_max_age = config->cu_max_age;
	sc->sc_hello_time = config->cu_hello_time;
	sc->sc_forward_delay = config->cu_forward_delay;
	sc->sc_topology_change = config->cu_topology_change;
}

void
bstp_config_bpdu_generation(struct bridge_softc *sc)
{
	struct bridge_iflist *bif;

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		if (bstp_designated_port(sc, bif) &&
		    (bif->bif_state != BSTP_IFSTATE_DISABLED))
			bstp_transmit_config(sc, bif);
	}
}

int
bstp_designated_port(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	return ((bif->bif_designated_bridge == sc->sc_bridge_id)
	    && (bif->bif_designated_port == bif->bif_port_id));
}

void
bstp_transmit_tcn(struct bridge_softc *sc)
{
	struct bstp_tbpdu bpdu;
	struct bridge_iflist *bif = sc->sc_root_port;
	struct ifnet *ifp;
	struct ether_header *eh;
	struct mbuf *m;

	KASSERT(bif != NULL, "bstp_transmit_tcn bif NULL");
	ifp = bif->bif_ifp;
	if ((ifp->if_flags & IFF_RUNNING) == 0)
		return;

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return;

	m->m_pkthdr.rcvif = ifp;
	m->m_pkthdr.len = sizeof(*eh) + sizeof(bpdu);
	m->m_len = m->m_pkthdr.len;

	eh = mtod(m, struct ether_header *);

	memcpy(eh->ether_shost, ifnet_lladdr(ifp), ETHER_ADDR_LEN);
	memcpy(eh->ether_dhost, bstp_etheraddr, ETHER_ADDR_LEN);
	eh->ether_type = htons(sizeof(bpdu));

	bpdu.tbu_ssap = bpdu.tbu_dsap = LLC_8021D_LSAP;
	bpdu.tbu_ctl = LLC_UI;
	bpdu.tbu_protoid = 0;
	bpdu.tbu_protover = 0;
	bpdu.tbu_bpdutype = BSTP_MSGTYPE_TCN;

	memcpy(mtod(m, caddr_t) + sizeof(*eh), &bpdu, sizeof(bpdu));

	bridge_enqueue(sc, ifp, m); // APPLE MODIFICATION - no flags param
}

void
bstp_configuration_update(struct bridge_softc *sc)
{
	bstp_root_selection(sc);
	bstp_designated_port_selection(sc);
}

void
bstp_root_selection(struct bridge_softc *sc)
{
	struct bridge_iflist *root_port = NULL, *bif;

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		if (bstp_designated_port(sc, bif))
			continue;
		if (bif->bif_state == BSTP_IFSTATE_DISABLED)
			continue;
		if (bif->bif_designated_root >= sc->sc_bridge_id)
			continue;
		if (root_port == NULL)
			goto set_port;

		if (bif->bif_designated_root < root_port->bif_designated_root)
			goto set_port;
		if (bif->bif_designated_root > root_port->bif_designated_root)
			continue;

		if ((bif->bif_designated_cost + bif->bif_path_cost) <
		    (root_port->bif_designated_cost + root_port->bif_path_cost))
			goto set_port;
		if ((bif->bif_designated_cost + bif->bif_path_cost) >
		    (root_port->bif_designated_cost + root_port->bif_path_cost))
			continue;

		if (bif->bif_designated_bridge <
		    root_port->bif_designated_bridge)
			goto set_port;
		if (bif->bif_designated_bridge >
		    root_port->bif_designated_bridge)
			continue;

		if (bif->bif_designated_port < root_port->bif_designated_port)
			goto set_port;
		if (bif->bif_designated_port > root_port->bif_designated_port)
			continue;

		if (bif->bif_port_id >= root_port->bif_port_id)
			continue;
set_port:
		root_port = bif;
	}

	sc->sc_root_port = root_port;
	if (root_port == NULL) {
		sc->sc_designated_root = sc->sc_bridge_id;
		sc->sc_root_path_cost = 0;
	} else {
		sc->sc_designated_root = root_port->bif_designated_root;
		sc->sc_root_path_cost = root_port->bif_designated_cost +
		    root_port->bif_path_cost;
	}
}

void
bstp_designated_port_selection(struct bridge_softc *sc)
{
	struct bridge_iflist *bif;

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		if (bstp_designated_port(sc, bif))
			goto designated;
		if (bif->bif_designated_root != sc->sc_designated_root)
			goto designated;

		if (sc->sc_root_path_cost < bif->bif_designated_cost)
			goto designated;
		if (sc->sc_root_path_cost > bif->bif_designated_cost)
			continue;

		if (sc->sc_bridge_id < bif->bif_designated_bridge)
			goto designated;
		if (sc->sc_bridge_id > bif->bif_designated_bridge)
			continue;

		if (bif->bif_port_id > bif->bif_designated_port)
			continue;
designated:
		bstp_become_designated_port(sc, bif);
	}
}

void
bstp_become_designated_port(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	bif->bif_designated_root = sc->sc_designated_root;
	bif->bif_designated_cost = sc->sc_root_path_cost;
	bif->bif_designated_bridge = sc->sc_bridge_id;
	bif->bif_designated_port = bif->bif_port_id;
}

void
bstp_port_state_selection(struct bridge_softc *sc)
{
	struct bridge_iflist *bif;

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		if (bif == sc->sc_root_port) {
			bif->bif_config_pending = 0;
			bif->bif_topology_change_acknowledge = 0;
			bstp_make_forwarding(sc, bif);
		} else if (bstp_designated_port(sc, bif)) {
			bstp_timer_stop(&bif->bif_message_age_timer);
			bstp_make_forwarding(sc, bif);
		} else {
			bif->bif_config_pending = 0;
			bif->bif_topology_change_acknowledge = 0;
			bstp_make_blocking(sc, bif);
		}
	}
}

void
bstp_make_forwarding(__unused struct bridge_softc *sc,
    struct bridge_iflist *bif)
{
	if (bif->bif_state == BSTP_IFSTATE_BLOCKING) {
		bstp_set_port_state(bif, BSTP_IFSTATE_LISTENING);
		bstp_timer_start(&bif->bif_forward_delay_timer, 0);
	}
}

void
bstp_make_blocking(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	if ((bif->bif_state != BSTP_IFSTATE_DISABLED) &&
	    (bif->bif_state != BSTP_IFSTATE_BLOCKING)) {
		if ((bif->bif_state == BSTP_IFSTATE_FORWARDING) ||
		    (bif->bif_state == BSTP_IFSTATE_LEARNING)) {
			if (bif->bif_change_detection_enabled) {
				bstp_topology_change_detection(sc);
			}
		}
		bstp_set_port_state(bif, BSTP_IFSTATE_BLOCKING);
		bstp_timer_stop(&bif->bif_forward_delay_timer);
	}
}

void
bstp_set_port_state(struct bridge_iflist *bif, uint8_t state)
{
	bif->bif_state = state;
}

void
bstp_topology_change_detection(struct bridge_softc *sc)
{
	if (bstp_root_bridge(sc)) {
		sc->sc_topology_change = 1;
		bstp_timer_start(&sc->sc_topology_change_timer, 0);
	} else if (!sc->sc_topology_change_detected) {
		bstp_transmit_tcn(sc);
		bstp_timer_start(&sc->sc_tcn_timer, 0);
	}
	sc->sc_topology_change_detected = 1;
}

void
bstp_topology_change_acknowledged(struct bridge_softc *sc)
{
	sc->sc_topology_change_detected = 0;
	bstp_timer_stop(&sc->sc_tcn_timer);
}

void
bstp_acknowledge_topology_change(struct bridge_softc *sc,
    struct bridge_iflist *bif)
{
	bif->bif_topology_change_acknowledge = 1;
	bstp_transmit_config(sc, bif);
}

__private_extern__ struct mbuf *
bstp_input(struct bridge_softc *sc, struct ifnet *ifp, struct mbuf *m)
{
	struct bridge_iflist *bif = NULL;
	struct ether_header *eh;
	struct bstp_tbpdu tpdu;
	struct bstp_cbpdu cpdu;
	struct bstp_config_unit cu;
	struct bstp_tcn_unit tu;
	uint16_t len;

	eh = mtod(m, struct ether_header *);

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		if (bif->bif_ifp == ifp)
			break;
	}
	if (bif == NULL)
		goto out;

	len = ntohs(eh->ether_type);
	if (len < sizeof(tpdu))
		goto out;

	m_adj(m, ETHER_HDR_LEN);

	if (m->m_pkthdr.len > len)
		m_adj(m, len - m->m_pkthdr.len);
	if ((size_t)m->m_len < sizeof(tpdu) &&
	    (m = m_pullup(m, sizeof(tpdu))) == NULL)
		goto out;

	memcpy(&tpdu, mtod(m, caddr_t), sizeof(tpdu));

	if (tpdu.tbu_dsap != LLC_8021D_LSAP ||
	    tpdu.tbu_ssap != LLC_8021D_LSAP ||
	    tpdu.tbu_ctl != LLC_UI)
		goto out;
	if (tpdu.tbu_protoid != 0 || tpdu.tbu_protover != 0)
		goto out;

	switch (tpdu.tbu_bpdutype) {
	case BSTP_MSGTYPE_TCN:
		tu.tu_message_type = tpdu.tbu_bpdutype;
		bstp_received_tcn_bpdu(sc, bif, &tu);
		break;
	case BSTP_MSGTYPE_CFG:
		if ((size_t)m->m_len < sizeof(cpdu) &&
		    (m = m_pullup(m, sizeof(cpdu))) == NULL)
			goto out;
		memcpy(&cpdu, mtod(m, caddr_t), sizeof(cpdu));

		cu.cu_rootid =
		    (((uint64_t)ntohs(cpdu.cbu_rootpri)) << 48) |
		    (((uint64_t)cpdu.cbu_rootaddr[0]) << 40) |
		    (((uint64_t)cpdu.cbu_rootaddr[1]) << 32) |
		    (((uint64_t)cpdu.cbu_rootaddr[2]) << 24) |
		    (((uint64_t)cpdu.cbu_rootaddr[3]) << 16) |
		    (((uint64_t)cpdu.cbu_rootaddr[4]) << 8) |
		    (((uint64_t)cpdu.cbu_rootaddr[5]) << 0);

		cu.cu_bridge_id =
		    (((uint64_t)ntohs(cpdu.cbu_bridgepri)) << 48) |
		    (((uint64_t)cpdu.cbu_bridgeaddr[0]) << 40) |
		    (((uint64_t)cpdu.cbu_bridgeaddr[1]) << 32) |
		    (((uint64_t)cpdu.cbu_bridgeaddr[2]) << 24) |
		    (((uint64_t)cpdu.cbu_bridgeaddr[3]) << 16) |
		    (((uint64_t)cpdu.cbu_bridgeaddr[4]) << 8) |
		    (((uint64_t)cpdu.cbu_bridgeaddr[5]) << 0);

		cu.cu_root_path_cost = ntohl(cpdu.cbu_rootpathcost);
		cu.cu_message_age = ntohs(cpdu.cbu_messageage);
		cu.cu_max_age = ntohs(cpdu.cbu_maxage);
		cu.cu_hello_time = ntohs(cpdu.cbu_hellotime);
		cu.cu_forward_delay = ntohs(cpdu.cbu_forwarddelay);
		cu.cu_port_id = ntohs(cpdu.cbu_portid);
		cu.cu_message_type = cpdu.cbu_bpdutype;
		cu.cu_topology_change_acknowledgment =
		    (cpdu.cbu_flags & BSTP_FLAG_TCA) ? 1 : 0;
		cu.cu_topology_change =
		    (cpdu.cbu_flags & BSTP_FLAG_TC) ? 1 : 0;
		bstp_received_config_bpdu(sc, bif, &cu);
		break;
	default:
		goto out;
	}

 out:
	if (m)
		m_freem(m);
	return (NULL);
}

void
bstp_received_config_bpdu(struct bridge_softc *sc, struct bridge_iflist *bif,
    struct bstp_config_unit *cu)
{
	int root;

	root = bstp_root_bridge(sc);

	if (bif->bif_state != BSTP_IFSTATE_DISABLED) {
		if (bstp_supersedes_port_info(sc, bif, cu)) {
			bstp_record_config_information(sc, bif, cu);
			bstp_configuration_update(sc);
			bstp_port_state_selection(sc);

			if ((bstp_root_bridge(sc) == 0) && root) {
				bstp_timer_stop(&sc->sc_hello_timer);

				if (sc->sc_topology_change_detected) {
					bstp_timer_stop(
					    &sc->sc_topology_change_timer);
					bstp_transmit_tcn(sc);
					bstp_timer_start(&sc->sc_tcn_timer, 0);
				}
			}

			if (bif == sc->sc_root_port) {
				bstp_record_config_timeout_values(sc, cu);
				bstp_config_bpdu_generation(sc);

				if (cu->cu_topology_change_acknowledgment)
					bstp_topology_change_acknowledged(sc);
			}
		} else if (bstp_designated_port(sc, bif))
			bstp_transmit_config(sc, bif);
	}
}

void
bstp_received_tcn_bpdu(struct bridge_softc *sc, struct bridge_iflist *bif,
    __unused struct bstp_tcn_unit *tcn)
{
	if (bif->bif_state != BSTP_IFSTATE_DISABLED &&
	    bstp_designated_port(sc, bif)) {
		bstp_topology_change_detection(sc);
		bstp_acknowledge_topology_change(sc, bif);
	}
}

void
bstp_hello_timer_expiry(struct bridge_softc *sc)
{
	bstp_config_bpdu_generation(sc);
	bstp_timer_start(&sc->sc_hello_timer, 0);
}

void
bstp_message_age_timer_expiry(struct bridge_softc *sc,
    struct bridge_iflist *bif)
{
	int root;

	root = bstp_root_bridge(sc);
	bstp_become_designated_port(sc, bif);
	bstp_configuration_update(sc);
	bstp_port_state_selection(sc);

	if ((bstp_root_bridge(sc)) && (root == 0)) {
		sc->sc_max_age = sc->sc_bridge_max_age;
		sc->sc_hello_time = sc->sc_bridge_hello_time;
		sc->sc_forward_delay = sc->sc_bridge_forward_delay;

		bstp_topology_change_detection(sc);
		bstp_timer_stop(&sc->sc_tcn_timer);
		bstp_config_bpdu_generation(sc);
		bstp_timer_start(&sc->sc_hello_timer, 0);
	}
}

void
bstp_forward_delay_timer_expiry(struct bridge_softc *sc,
    struct bridge_iflist *bif)
{
	if (bif->bif_state == BSTP_IFSTATE_LISTENING) {
		bstp_set_port_state(bif, BSTP_IFSTATE_LEARNING);
		bstp_timer_start(&bif->bif_forward_delay_timer, 0);
	} else if (bif->bif_state == BSTP_IFSTATE_LEARNING) {
		bstp_set_port_state(bif, BSTP_IFSTATE_FORWARDING);
		if (bstp_designated_for_some_port(sc) &&
		    bif->bif_change_detection_enabled)
			bstp_topology_change_detection(sc);
	}
}

int
bstp_designated_for_some_port(struct bridge_softc *sc)
{

	struct bridge_iflist *bif;

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		if (bif->bif_designated_bridge == sc->sc_bridge_id)
			return (1);
	}
	return (0);
}

void
bstp_tcn_timer_expiry(struct bridge_softc *sc)
{
	bstp_transmit_tcn(sc);
	bstp_timer_start(&sc->sc_tcn_timer, 0);
}

void
bstp_topology_change_timer_expiry(struct bridge_softc *sc)
{
	sc->sc_topology_change_detected = 0;
	sc->sc_topology_change = 0;
}

void
bstp_hold_timer_expiry(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	if (bif->bif_config_pending)
		bstp_transmit_config(sc, bif);
}

__private_extern__ void
bstp_initialization(struct bridge_softc *sc)
{
	struct bridge_iflist *bif, *mif;
	struct timespec ts;
	unsigned char *lladdr;

	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);

	mif = NULL;
	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		if (bif->bif_ifp->if_type != IFT_ETHER)
			continue;
		bif->bif_port_id = (bif->bif_priority << 8) |
		    (bif->bif_ifp->if_index & 0xff);

		if (mif == NULL) {
			mif = bif;
			continue;
		}
		if (memcmp(ifnet_lladdr(bif->bif_ifp),
		    ifnet_lladdr(mif->bif_ifp), ETHER_ADDR_LEN) < 0) {
			mif = bif;
			continue;
		}
	}
	if (mif == NULL) {
		bstp_stop(sc);
		return;
	}

	lladdr = ifnet_lladdr(mif->bif_ifp);
	sc->sc_bridge_id =
	    (((uint64_t)sc->sc_bridge_priority) << 48) |
	    (((uint64_t)lladdr[0]) << 40) |
	    (((uint64_t)lladdr[1]) << 32) |
	    (lladdr[2] << 24) |
	    (lladdr[3] << 16) |
	    (lladdr[4] << 8) |
	    (lladdr[5]);

	sc->sc_designated_root = sc->sc_bridge_id;
	sc->sc_root_path_cost = 0;
	sc->sc_root_port = NULL;

	sc->sc_max_age = sc->sc_bridge_max_age;
	sc->sc_hello_time = sc->sc_bridge_hello_time;
	sc->sc_forward_delay = sc->sc_bridge_forward_delay;
	sc->sc_topology_change_detected = 0;
	sc->sc_topology_change = 0;
	bstp_timer_stop(&sc->sc_tcn_timer);
	bstp_timer_stop(&sc->sc_topology_change_timer);

	bsd_untimeout(bstp_tick, sc);
	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	bsd_timeout(bstp_tick, sc, &ts);

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if (bif->bif_flags & IFBIF_STP)
			bstp_enable_port(sc, bif);
		else
			bstp_disable_port(sc, bif);
	}

	bstp_port_state_selection(sc);
	bstp_config_bpdu_generation(sc);
	bstp_timer_start(&sc->sc_hello_timer, 0);
}

__private_extern__ void
bstp_stop(struct bridge_softc *sc)
{
	struct bridge_iflist *bif;

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		bstp_set_port_state(bif, BSTP_IFSTATE_DISABLED);
		bstp_timer_stop(&bif->bif_hold_timer);
		bstp_timer_stop(&bif->bif_message_age_timer);
		bstp_timer_stop(&bif->bif_forward_delay_timer);
	}

	bsd_untimeout(bstp_tick, sc);

	bstp_timer_stop(&sc->sc_topology_change_timer);
	bstp_timer_stop(&sc->sc_tcn_timer);
	bstp_timer_stop(&sc->sc_hello_timer);

}

void
bstp_initialize_port(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	bstp_become_designated_port(sc, bif);
	bstp_set_port_state(bif, BSTP_IFSTATE_BLOCKING);
	bif->bif_topology_change_acknowledge = 0;
	bif->bif_config_pending = 0;
	bif->bif_change_detection_enabled = 1;
	bstp_timer_stop(&bif->bif_message_age_timer);
	bstp_timer_stop(&bif->bif_forward_delay_timer);
	bstp_timer_stop(&bif->bif_hold_timer);
}

void
bstp_enable_port(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	bstp_initialize_port(sc, bif);
	bstp_port_state_selection(sc);
}

void
bstp_disable_port(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	int root;

	root = bstp_root_bridge(sc);
	bstp_become_designated_port(sc, bif);
	bstp_set_port_state(bif, BSTP_IFSTATE_DISABLED);
	bif->bif_topology_change_acknowledge = 0;
	bif->bif_config_pending = 0;
	bstp_timer_stop(&bif->bif_message_age_timer);
	bstp_timer_stop(&bif->bif_forward_delay_timer);
	bstp_configuration_update(sc);
	bstp_port_state_selection(sc);

	if (bstp_root_bridge(sc) && (root == 0)) {
		sc->sc_max_age = sc->sc_bridge_max_age;
		sc->sc_hello_time = sc->sc_bridge_hello_time;
		sc->sc_forward_delay = sc->sc_bridge_forward_delay;

		bstp_topology_change_detection(sc);
		bstp_timer_stop(&sc->sc_tcn_timer);
		bstp_config_bpdu_generation(sc);
		bstp_timer_start(&sc->sc_hello_timer, 0);
	}
}

void
bstp_set_bridge_priority(struct bridge_softc *sc, uint64_t new_bridge_id)
{
	struct bridge_iflist *bif;
	int root;

	root = bstp_root_bridge(sc);

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		if (bstp_designated_port(sc, bif))
			bif->bif_designated_bridge = new_bridge_id;
	}

	sc->sc_bridge_id = new_bridge_id;

	bstp_configuration_update(sc);
	bstp_port_state_selection(sc);

	if (bstp_root_bridge(sc) && (root == 0)) {
		sc->sc_max_age = sc->sc_bridge_max_age;
		sc->sc_hello_time = sc->sc_bridge_hello_time;
		sc->sc_forward_delay = sc->sc_bridge_forward_delay;

		bstp_topology_change_detection(sc);
		bstp_timer_stop(&sc->sc_tcn_timer);
		bstp_config_bpdu_generation(sc);
		bstp_timer_start(&sc->sc_hello_timer, 0);
	}
}

void
bstp_set_port_priority(struct bridge_softc *sc, struct bridge_iflist *bif,
    uint16_t new_port_id)
{
	if (bstp_designated_port(sc, bif))
		bif->bif_designated_port = new_port_id;

	bif->bif_port_id = new_port_id;

	if ((sc->sc_bridge_id == bif->bif_designated_bridge) &&
	    (bif->bif_port_id < bif->bif_designated_port)) {
		bstp_become_designated_port(sc, bif);
		bstp_port_state_selection(sc);
	}
}

void
bstp_set_path_cost(struct bridge_softc *sc, struct bridge_iflist *bif,
    uint32_t path_cost)
{
	bif->bif_path_cost = path_cost;
	bstp_configuration_update(sc);
	bstp_port_state_selection(sc);
}

void
bstp_enable_change_detection(struct bridge_iflist *bif)
{
	bif->bif_change_detection_enabled = 1;
}

void
bstp_disable_change_detection(struct bridge_iflist *bif)
{
	bif->bif_change_detection_enabled = 0;
}

void
bstp_ifupdstatus(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	struct ifnet *ifp = bif->bif_ifp;
    struct ifmediareq   ifmr;

	if ((ifnet_flags(ifp) & IFF_UP)) {
		bzero(&ifmr, sizeof(ifmr));
		if (ifnet_ioctl(ifp, 0, SIOCGIFMEDIA, &ifmr) == 0) {
			// enable the port when the link is up, or its state is unknown
			if ((ifmr.ifm_status & IFM_ACTIVE) || !(ifmr.ifm_status & IFM_AVALID)) {
				if (bif->bif_state == BSTP_IFSTATE_DISABLED)
					bstp_enable_port(sc, bif);
			} else {
				if (bif->bif_state != BSTP_IFSTATE_DISABLED)
					bstp_disable_port(sc, bif);
			}
		}
		return;
	}

	if (bif->bif_state != BSTP_IFSTATE_DISABLED)
		bstp_disable_port(sc, bif);
}

void
bstp_tick(void *arg)
{
	struct bridge_softc *sc = arg;
	struct bridge_iflist *bif;
	struct timespec ts;

	lck_mtx_lock(sc->sc_mtx);

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		/*
		 * XXX This can cause a lag in "link does away"
		 * XXX and "spanning tree gets updated".  We need
		 * XXX come sort of callback from the link state
		 * XXX update code to kick spanning tree.
		 * XXX --thorpej@NetBSD.org
		 */
		bstp_ifupdstatus(sc, bif);
	}

	if (bstp_timer_expired(&sc->sc_hello_timer, sc->sc_hello_time))
		bstp_hello_timer_expiry(sc);

	if (bstp_timer_expired(&sc->sc_tcn_timer, sc->sc_bridge_hello_time))
		bstp_tcn_timer_expiry(sc);

	if (bstp_timer_expired(&sc->sc_topology_change_timer,
	    sc->sc_topology_change_time))
		bstp_topology_change_timer_expiry(sc);

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		if (bstp_timer_expired(&bif->bif_message_age_timer,
		    sc->sc_max_age))
			bstp_message_age_timer_expiry(sc, bif);
	}

	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if ((bif->bif_flags & IFBIF_STP) == 0)
			continue;
		if (bstp_timer_expired(&bif->bif_forward_delay_timer,
		    sc->sc_forward_delay))
			bstp_forward_delay_timer_expiry(sc, bif);

		if (bstp_timer_expired(&bif->bif_hold_timer,
		    sc->sc_hold_time))
			bstp_hold_timer_expiry(sc, bif);
	}

	lck_mtx_unlock(sc->sc_mtx);

	/* APPLE MODIFICATION - bridge changes */
	if (ifnet_flags(sc->sc_if) & IFF_RUNNING) {
		ts.tv_sec = 1;
		ts.tv_nsec = 0;
		bsd_timeout(bstp_tick, sc, &ts);
	}
}

void
bstp_timer_start(struct bridge_timer *t, uint16_t v)
{
	t->value = v;
	t->active = 1;
}

void
bstp_timer_stop(struct bridge_timer *t)
{
	t->value = 0;
	t->active = 0;
}

int
bstp_timer_expired(struct bridge_timer *t, uint16_t v)
{
	if (t->active == 0)
		return (0);
	t->value += BSTP_TICK_VAL;
	if (t->value >= v) {
		bstp_timer_stop(t);
		return (1);
	}
	return (0);

}
