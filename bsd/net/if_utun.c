/*
 * Copyright (c) 2008-2017 Apple Inc. All rights reserved.
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



/* ----------------------------------------------------------------------------------
Application of kernel control for interface creation

Theory of operation:
utun (user tunnel) acts as glue between kernel control sockets and network interfaces. 
This kernel control will register an interface for every client that connects. 
---------------------------------------------------------------------------------- */

#include <sys/systm.h>
#include <sys/kern_control.h>
#include <net/kpi_protocol.h>
#include <net/kpi_interface.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/if_utun.h>
#include <sys/mbuf.h> 
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_var.h>
#include <sys/kauth.h>
#include <net/necp.h>
#include <kern/zalloc.h>

#define UTUN_NEXUS 0

extern unsigned int if_enable_netagent;

#if UTUN_NEXUS
static nexus_controller_t utun_ncd;
static int utun_ncd_refcount;
static uuid_t utun_kpipe_uuid;
static uuid_t utun_nx_dom_prov;

typedef struct utun_nx {
	uuid_t if_provider;
	uuid_t if_instance;
	uuid_t ms_provider;
	uuid_t ms_instance;
	uuid_t ms_device;
	uuid_t ms_host;
	uuid_t ms_agent;
} *utun_nx_t;

#endif // UTUN_NEXUS

/* Control block allocated for each kernel control connection */
struct utun_pcb {
	TAILQ_ENTRY(utun_pcb)	utun_chain;
	kern_ctl_ref	utun_ctlref;
	ifnet_t			utun_ifp;
	u_int32_t		utun_unit;
	u_int32_t		utun_unique_id;
	u_int32_t		utun_flags;
	int				utun_ext_ifdata_stats;
	u_int32_t		utun_max_pending_packets;
	char			utun_if_xname[IFXNAMSIZ];
	char			utun_unique_name[IFXNAMSIZ];
	// PCB lock protects state fields and rings
	decl_lck_rw_data(, utun_pcb_lock);
	struct mbuf *	utun_input_chain;
	struct mbuf *	utun_input_chain_last;
	// Input chain lock protects the list of input mbufs
	// The input chain lock must be taken AFTER the PCB lock if both are held
	lck_mtx_t		utun_input_chain_lock;
	bool			utun_output_disabled;

#if UTUN_NEXUS
	struct utun_nx	utun_nx;
	int				utun_kpipe_enabled;
	uuid_t			utun_kpipe_uuid;
	void *			utun_kpipe_rxring;
	void *			utun_kpipe_txring;

	kern_nexus_t	utun_netif_nexus;
	void *			utun_netif_rxring;
	void *			utun_netif_txring;
	uint64_t		utun_netif_txring_size;
#endif // UTUN_NEXUS
};

/* Kernel Control functions */
static errno_t	utun_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac,
								 void **unitinfo);
static errno_t	utun_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t unit,
									void *unitinfo);
static errno_t	utun_ctl_send(kern_ctl_ref kctlref, u_int32_t unit,
							   void *unitinfo, mbuf_t m, int flags);
static errno_t	utun_ctl_getopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
								 int opt, void *data, size_t *len);
static errno_t	utun_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
								 int opt, void *data, size_t len);
static void		utun_ctl_rcvd(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
								int flags);

/* Network Interface functions */
#if !UTUN_NEXUS
static void     utun_start(ifnet_t interface);
static errno_t	utun_framer(ifnet_t interface, mbuf_t *packet,
							const struct sockaddr *dest, const char *desk_linkaddr,
							const char *frame_type, u_int32_t *prepend_len, u_int32_t *postpend_len);
#endif // !UTUN_NEXUS
static errno_t	utun_output(ifnet_t interface, mbuf_t data);
static errno_t	utun_demux(ifnet_t interface, mbuf_t data, char *frame_header,
						   protocol_family_t *protocol);
static errno_t	utun_add_proto(ifnet_t interface, protocol_family_t protocol,
							   const struct ifnet_demux_desc *demux_array,
							   u_int32_t demux_count);
static errno_t	utun_del_proto(ifnet_t interface, protocol_family_t protocol);
static errno_t	utun_ioctl(ifnet_t interface, u_long cmd, void *data);
static void		utun_detached(ifnet_t interface);

/* Protocol handlers */
static errno_t	utun_attach_proto(ifnet_t interface, protocol_family_t proto);
static errno_t	utun_proto_input(ifnet_t interface, protocol_family_t protocol,
								 mbuf_t m, char *frame_header);
static errno_t utun_proto_pre_output(ifnet_t interface, protocol_family_t protocol, 
					 mbuf_t *packet, const struct sockaddr *dest, void *route,
					 char *frame_type, char *link_layer_dest);
static errno_t utun_pkt_input (struct utun_pcb *pcb, mbuf_t m);

#if UTUN_NEXUS

#define UTUN_IF_DEFAULT_SLOT_SIZE 4096
#define UTUN_IF_DEFAULT_RING_SIZE 64
#define UTUN_IF_DEFAULT_TX_FSW_RING_SIZE 64
#define UTUN_IF_DEFAULT_RX_FSW_RING_SIZE 128
#define UTUN_IF_HEADROOM_SIZE 32

#define UTUN_IF_MIN_RING_SIZE 16
#define UTUN_IF_MAX_RING_SIZE 1024

static int sysctl_if_utun_ring_size SYSCTL_HANDLER_ARGS;
static int sysctl_if_utun_tx_fsw_ring_size SYSCTL_HANDLER_ARGS;
static int sysctl_if_utun_rx_fsw_ring_size SYSCTL_HANDLER_ARGS;

static int if_utun_ring_size = UTUN_IF_DEFAULT_RING_SIZE;
static int if_utun_tx_fsw_ring_size = UTUN_IF_DEFAULT_TX_FSW_RING_SIZE;
static int if_utun_rx_fsw_ring_size = UTUN_IF_DEFAULT_RX_FSW_RING_SIZE;

SYSCTL_DECL(_net_utun);
SYSCTL_NODE(_net, OID_AUTO, utun, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "UTun");

SYSCTL_PROC(_net_utun, OID_AUTO, ring_size, CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW,
			&if_utun_ring_size, UTUN_IF_DEFAULT_RING_SIZE, &sysctl_if_utun_ring_size, "I", "");
SYSCTL_PROC(_net_utun, OID_AUTO, tx_fsw_ring_size, CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW,
			&if_utun_tx_fsw_ring_size, UTUN_IF_DEFAULT_TX_FSW_RING_SIZE, &sysctl_if_utun_tx_fsw_ring_size, "I", "");
SYSCTL_PROC(_net_utun, OID_AUTO, rx_fsw_ring_size, CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW,
			&if_utun_rx_fsw_ring_size, UTUN_IF_DEFAULT_RX_FSW_RING_SIZE, &sysctl_if_utun_rx_fsw_ring_size, "I", "");

static errno_t
utun_register_nexus(void);

static errno_t
utun_netif_prepare(__unused kern_nexus_t nexus, ifnet_t ifp);
static errno_t
utun_nexus_pre_connect(kern_nexus_provider_t nxprov,
    proc_t p, kern_nexus_t nexus,
    nexus_port_t nexus_port, kern_channel_t channel, void **ch_ctx);
static errno_t
utun_nexus_connected(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel);
static void
utun_netif_pre_disconnect(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel);
static void
utun_nexus_pre_disconnect(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
	kern_channel_t channel);
static void
utun_nexus_disconnected(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel);
static errno_t
utun_kpipe_ring_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel, kern_channel_ring_t ring, boolean_t is_tx_ring,
    void **ring_ctx);
static void
utun_kpipe_ring_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring);
static errno_t
utun_kpipe_sync_tx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, uint32_t flags);
static errno_t
utun_kpipe_sync_rx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, uint32_t flags);
#endif // UTUN_NEXUS

#define UTUN_DEFAULT_MTU 1500
#define UTUN_HEADER_SIZE(_pcb) (sizeof(u_int32_t) + (((_pcb)->utun_flags & UTUN_FLAGS_ENABLE_PROC_UUID) ? sizeof(uuid_t) : 0))

static kern_ctl_ref	utun_kctlref;
static u_int32_t	utun_family;
static lck_attr_t *utun_lck_attr;
static lck_grp_attr_t *utun_lck_grp_attr;
static lck_grp_t *utun_lck_grp;
static lck_mtx_t utun_lock;

TAILQ_HEAD(utun_list, utun_pcb) utun_head;

#define	UTUN_PCB_ZONE_MAX		32
#define	UTUN_PCB_ZONE_NAME		"net.if_utun"

static unsigned int utun_pcb_size;		/* size of zone element */
static struct zone *utun_pcb_zone;		/* zone for utun_pcb */

#if UTUN_NEXUS

static int
sysctl_if_utun_ring_size SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int value = if_utun_ring_size;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr) {
		return (error);
	}

	if (value < UTUN_IF_MIN_RING_SIZE ||
		value > UTUN_IF_MAX_RING_SIZE) {
		return (EINVAL);
	}

	if_utun_ring_size = value;

	return (0);
}

static int
sysctl_if_utun_tx_fsw_ring_size SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int value = if_utun_tx_fsw_ring_size;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr) {
		return (error);
	}

	if (value < UTUN_IF_MIN_RING_SIZE ||
		value > UTUN_IF_MAX_RING_SIZE) {
		return (EINVAL);
	}

	if_utun_tx_fsw_ring_size = value;

	return (0);
}

static int
sysctl_if_utun_rx_fsw_ring_size SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int value = if_utun_rx_fsw_ring_size;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr) {
		return (error);
	}

	if (value < UTUN_IF_MIN_RING_SIZE ||
		value > UTUN_IF_MAX_RING_SIZE) {
		return (EINVAL);
	}

	if_utun_rx_fsw_ring_size = value;

	return (0);
}

static errno_t
utun_netif_ring_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
					 kern_channel_t channel, kern_channel_ring_t ring, boolean_t is_tx_ring,
					 void **ring_ctx)
{
#pragma unused(nxprov)
#pragma unused(channel)
#pragma unused(ring_ctx)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);
	if (!is_tx_ring) {
		VERIFY(pcb->utun_netif_rxring == NULL);
		pcb->utun_netif_rxring = ring;
	} else {
		VERIFY(pcb->utun_netif_txring == NULL);
		pcb->utun_netif_txring = ring;
	}
	return 0;
}

static void
utun_netif_ring_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
					 kern_channel_ring_t ring)
{
#pragma unused(nxprov)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);
	if (pcb->utun_netif_rxring == ring) {
		pcb->utun_netif_rxring = NULL;
	} else if (pcb->utun_netif_txring == ring) {
		pcb->utun_netif_txring = NULL;
	}
}

static errno_t
utun_netif_sync_tx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
				   kern_channel_ring_t tx_ring, uint32_t flags)
{
#pragma unused(nxprov)
#pragma unused(flags)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);

	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;

	lck_rw_lock_shared(&pcb->utun_pcb_lock);

	struct kern_channel_ring_stat_increment tx_ring_stats;
	bzero(&tx_ring_stats, sizeof(tx_ring_stats));
	kern_channel_slot_t tx_pslot = NULL;
	kern_channel_slot_t tx_slot = kern_channel_get_next_slot(tx_ring, NULL, NULL);

	STATS_INC(nifs, NETIF_STATS_TXSYNC);

	if (tx_slot == NULL) {
		// Nothing to write, don't bother signalling
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		return 0;
	}

	if (pcb->utun_kpipe_enabled) {
		kern_channel_ring_t rx_ring = pcb->utun_kpipe_rxring;
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);

		// Signal the kernel pipe ring to read
		if (rx_ring != NULL) {
			kern_channel_notify(rx_ring, 0);
		}
		return 0;
	}

	// If we're here, we're injecting into the utun kernel control socket
	while (tx_slot != NULL) {
		size_t length = 0;
		mbuf_t data = NULL;

		kern_packet_t tx_ph = kern_channel_slot_get_packet(tx_ring, tx_slot);

		if (tx_ph == 0) {
			// Advance TX ring
			tx_pslot = tx_slot;
			tx_slot = kern_channel_get_next_slot(tx_ring, tx_slot, NULL);
			continue;
		}
		(void) kern_channel_slot_detach_packet(tx_ring, tx_slot, tx_ph);

		// Advance TX ring
		tx_pslot = tx_slot;
		tx_slot = kern_channel_get_next_slot(tx_ring, tx_slot, NULL);

		kern_buflet_t tx_buf = kern_packet_get_next_buflet(tx_ph, NULL);
		VERIFY(tx_buf != NULL);

		/* tx_baddr is the absolute buffer address */
		uint8_t *tx_baddr = kern_buflet_get_object_address(tx_buf);
		VERIFY(tx_baddr != 0);

		bpf_tap_packet_out(pcb->utun_ifp, DLT_RAW, tx_ph, NULL, 0);

		uint16_t tx_offset = kern_buflet_get_data_offset(tx_buf);
		uint32_t tx_length = kern_buflet_get_data_length(tx_buf);

		// The offset must be large enough for the headers
		VERIFY(tx_offset >= UTUN_HEADER_SIZE(pcb));

		// Find family
		uint32_t af = 0;
		uint8_t vhl = *(uint8_t *)(tx_baddr + tx_offset);
		u_int ip_version = (vhl >> 4);
		switch (ip_version) {
			case 4: {
				af = AF_INET;
				break;
			}
			case 6: {
				af = AF_INET6;
				break;
			}
			default: {
				printf("utun_netif_sync_tx %s: unknown ip version %u vhl %u tx_offset %u len %u header_size %zu\n",
					   pcb->utun_ifp->if_xname, ip_version, vhl, tx_offset, tx_length,
					   UTUN_HEADER_SIZE(pcb));
				break;
			}
		}

		tx_offset -= UTUN_HEADER_SIZE(pcb);
		tx_length += UTUN_HEADER_SIZE(pcb);
		tx_baddr += tx_offset;

		length = MIN(tx_length, UTUN_IF_DEFAULT_SLOT_SIZE);

		// Copy in family
		memcpy(tx_baddr, &af, sizeof(af));
		if (pcb->utun_flags & UTUN_FLAGS_ENABLE_PROC_UUID) {
			kern_packet_get_euuid(tx_ph, (void *)(tx_baddr + sizeof(af)));
		}

		if (length > 0) {
			errno_t error = mbuf_gethdr(MBUF_DONTWAIT, MBUF_TYPE_HEADER, &data);
			if (error == 0) {
				error = mbuf_copyback(data, 0, length, tx_baddr, MBUF_DONTWAIT);
				if (error == 0) {
					error = utun_output(pcb->utun_ifp, data);
					if (error != 0) {
						printf("utun_netif_sync_tx %s - utun_output error %d\n", pcb->utun_ifp->if_xname, error);
					}
				} else {
					printf("utun_netif_sync_tx %s - mbuf_copyback(%zu) error %d\n", pcb->utun_ifp->if_xname, length, error);
					STATS_INC(nifs, NETIF_STATS_NOMEM_MBUF);
					STATS_INC(nifs, NETIF_STATS_DROPPED);
					mbuf_freem(data);
					data = NULL;
				}
			} else {
				printf("utun_netif_sync_tx %s - mbuf_gethdr error %d\n", pcb->utun_ifp->if_xname, error);
				STATS_INC(nifs, NETIF_STATS_NOMEM_MBUF);
				STATS_INC(nifs, NETIF_STATS_DROPPED);
			}
		} else {
			printf("utun_netif_sync_tx %s - 0 length packet\n", pcb->utun_ifp->if_xname);
			STATS_INC(nifs, NETIF_STATS_NOMEM_MBUF);
			STATS_INC(nifs, NETIF_STATS_DROPPED);
		}

		kern_pbufpool_free(tx_ring->ckr_pp, tx_ph);

		if (data == NULL) {
			continue;
		}

		STATS_INC(nifs, NETIF_STATS_TXPKTS);
		STATS_INC(nifs, NETIF_STATS_TXCOPY_MBUF);

		tx_ring_stats.kcrsi_slots_transferred++;
		tx_ring_stats.kcrsi_bytes_transferred += length;
	}

	if (tx_pslot) {
		kern_channel_advance_slot(tx_ring, tx_pslot);
		kern_channel_increment_ring_net_stats(tx_ring, pcb->utun_ifp, &tx_ring_stats);
		(void)kern_channel_reclaim(tx_ring);
	}

	lck_rw_unlock_shared(&pcb->utun_pcb_lock);

	return 0;
}

static errno_t
utun_netif_tx_doorbell(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
					   kern_channel_ring_t ring, __unused uint32_t flags)
{
#pragma unused(nxprov)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);

	lck_rw_lock_shared(&pcb->utun_pcb_lock);

	boolean_t more = false;
	errno_t rc = 0;
	do {
		/* Refill and sync the ring */
		rc = kern_channel_tx_refill(ring, UINT32_MAX, UINT32_MAX, true, &more);
		if (rc != 0 && rc != EAGAIN && rc != EBUSY) {
			printf("%s, tx refill failed %d\n", __func__, rc);
		}
	} while ((rc == 0) && more);

	if (pcb->utun_kpipe_enabled && !pcb->utun_output_disabled) {
		uint32_t tx_available = kern_channel_available_slot_count(ring);
		if (pcb->utun_netif_txring_size > 0 &&
			tx_available >= pcb->utun_netif_txring_size - 1) {
			// No room left in tx ring, disable output for now
			errno_t error = ifnet_disable_output(pcb->utun_ifp);
			if (error != 0) {
				printf("utun_netif_tx_doorbell: ifnet_disable_output returned error %d\n", error);
			} else {
				pcb->utun_output_disabled = true;
			}
		}
	}

	if (pcb->utun_kpipe_enabled &&
		(((rc != 0) && (rc != EAGAIN)) || pcb->utun_output_disabled)) {
		kern_channel_ring_t rx_ring = pcb->utun_kpipe_rxring;

		// Unlock while calling notify
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		// Signal the kernel pipe ring to read
		if (rx_ring != NULL) {
			kern_channel_notify(rx_ring, 0);
		}
	} else {
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
	}

	return (0);
}

static errno_t
utun_netif_sync_rx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
				   kern_channel_ring_t rx_ring, uint32_t flags)
{
#pragma unused(nxprov)
#pragma unused(flags)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);
	struct kern_channel_ring_stat_increment rx_ring_stats;

	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;

	lck_rw_lock_shared(&pcb->utun_pcb_lock);

	// Reclaim user-released slots
	(void) kern_channel_reclaim(rx_ring);

	STATS_INC(nifs, NETIF_STATS_RXSYNC);

	uint32_t avail = kern_channel_available_slot_count(rx_ring);
	if (avail == 0) {
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		return 0;
	}

	struct kern_pbufpool *rx_pp = rx_ring->ckr_pp;
	VERIFY(rx_pp != NULL);
	bzero(&rx_ring_stats, sizeof(rx_ring_stats));
	kern_channel_slot_t rx_pslot = NULL;
	kern_channel_slot_t rx_slot = kern_channel_get_next_slot(rx_ring, NULL, NULL);

	while (rx_slot != NULL) {
		// Check for a waiting packet
		lck_mtx_lock(&pcb->utun_input_chain_lock);
		mbuf_t data = pcb->utun_input_chain;
		if (data == NULL) {
			lck_mtx_unlock(&pcb->utun_input_chain_lock);
			break;
		}

		// Allocate rx packet
		kern_packet_t rx_ph = 0;
		errno_t error = kern_pbufpool_alloc_nosleep(rx_pp, 1, &rx_ph);
		if (unlikely(error != 0)) {
			STATS_INC(nifs, NETIF_STATS_NOMEM_PKT);
			STATS_INC(nifs, NETIF_STATS_DROPPED);
			printf("utun_netif_sync_rx %s: failed to allocate packet\n",
				   pcb->utun_ifp->if_xname);
			lck_mtx_unlock(&pcb->utun_input_chain_lock);
			break;
		}

		// Advance waiting packets
		pcb->utun_input_chain = data->m_nextpkt;
		data->m_nextpkt = NULL;
		if (pcb->utun_input_chain == NULL) {
			pcb->utun_input_chain_last = NULL;
		}
		lck_mtx_unlock(&pcb->utun_input_chain_lock);

		size_t header_offset = UTUN_HEADER_SIZE(pcb);
		size_t length = mbuf_pkthdr_len(data);

		if (length < header_offset) {
			// mbuf is too small
			mbuf_freem(data);
			kern_pbufpool_free(rx_pp, rx_ph);
			STATS_INC(nifs, NETIF_STATS_BADLEN);
			STATS_INC(nifs, NETIF_STATS_DROPPED);
			printf("utun_netif_sync_rx %s: legacy packet length too short for header %zu < %zu\n",
				   pcb->utun_ifp->if_xname, length, header_offset);
			continue;
		}

		length -= header_offset;
		if (length > rx_pp->pp_buflet_size) {
			// Flush data
			mbuf_freem(data);
			kern_pbufpool_free(rx_pp, rx_ph);
			STATS_INC(nifs, NETIF_STATS_BADLEN);
			STATS_INC(nifs, NETIF_STATS_DROPPED);
			printf("utun_netif_sync_rx %s: legacy packet length %zu > %u\n",
				   pcb->utun_ifp->if_xname, length, rx_pp->pp_buflet_size);
			continue;
		}

		mbuf_pkthdr_setrcvif(data, pcb->utun_ifp);

		// Fillout rx packet
		kern_buflet_t rx_buf = kern_packet_get_next_buflet(rx_ph, NULL);
		VERIFY(rx_buf != NULL);
		void *rx_baddr = kern_buflet_get_object_address(rx_buf);
		VERIFY(rx_baddr != NULL);

		// Copy-in data from mbuf to buflet
		mbuf_copydata(data, header_offset, length, (void *)rx_baddr);
		kern_packet_clear_flow_uuid(rx_ph);	// Zero flow id

		// Finalize and attach the packet
		error = kern_buflet_set_data_offset(rx_buf, 0);
		VERIFY(error == 0);
		error = kern_buflet_set_data_length(rx_buf, length);
		VERIFY(error == 0);
		error = kern_packet_set_link_header_offset(rx_ph, 0);
		VERIFY(error == 0);
		error = kern_packet_set_network_header_offset(rx_ph, 0);
		VERIFY(error == 0);
		error = kern_packet_finalize(rx_ph);
		VERIFY(error == 0);
		error = kern_channel_slot_attach_packet(rx_ring, rx_slot, rx_ph);
		VERIFY(error == 0);

		STATS_INC(nifs, NETIF_STATS_RXPKTS);
		STATS_INC(nifs, NETIF_STATS_RXCOPY_MBUF);
		bpf_tap_packet_in(pcb->utun_ifp, DLT_RAW, rx_ph, NULL, 0);

		rx_ring_stats.kcrsi_slots_transferred++;
		rx_ring_stats.kcrsi_bytes_transferred += length;

		mbuf_freem(data);

		// Advance ring
		rx_pslot = rx_slot;
		rx_slot = kern_channel_get_next_slot(rx_ring, rx_slot, NULL);
	}

	struct kern_channel_ring_stat_increment tx_ring_stats;
	bzero(&tx_ring_stats, sizeof(tx_ring_stats));
	kern_channel_ring_t tx_ring = pcb->utun_kpipe_txring;
	kern_channel_slot_t tx_pslot = NULL;
	kern_channel_slot_t tx_slot = NULL;
	if (tx_ring == NULL) {
		// Net-If TX ring not set up yet, nothing to read
		goto done;
	}

	// Unlock utun before entering ring
	lck_rw_unlock_shared(&pcb->utun_pcb_lock);

	(void)kr_enter(tx_ring, TRUE);

	// Lock again after entering and validate
	lck_rw_lock_shared(&pcb->utun_pcb_lock);
	if (tx_ring != pcb->utun_kpipe_txring) {
		goto done;
	}

	tx_slot = kern_channel_get_next_slot(tx_ring, NULL, NULL);
	if (tx_slot == NULL) {
		// Nothing to read, don't bother signalling
		goto done;
	}

	while (rx_slot != NULL && tx_slot != NULL) {
		// Allocate rx packet
		kern_packet_t rx_ph = 0;
		kern_packet_t tx_ph = kern_channel_slot_get_packet(tx_ring, tx_slot);

		// Advance TX ring
		tx_pslot = tx_slot;
		tx_slot = kern_channel_get_next_slot(tx_ring, tx_slot, NULL);

		/* Skip slot if packet is zero-length or marked as dropped (QUMF_DROPPED) */
		if (tx_ph == 0) {
			continue;
		}

		errno_t error = kern_pbufpool_alloc_nosleep(rx_pp, 1, &rx_ph);
		if (unlikely(error != 0)) {
			STATS_INC(nifs, NETIF_STATS_NOMEM_PKT);
			STATS_INC(nifs, NETIF_STATS_DROPPED);
			printf("utun_netif_sync_rx %s: failed to allocate packet\n",
				   pcb->utun_ifp->if_xname);
			break;
		}

		kern_buflet_t tx_buf = kern_packet_get_next_buflet(tx_ph, NULL);
		VERIFY(tx_buf != NULL);
		uint8_t *tx_baddr = kern_buflet_get_object_address(tx_buf);
		VERIFY(tx_baddr != 0);
		tx_baddr += kern_buflet_get_data_offset(tx_buf);

		// Check packet length
		size_t header_offset = UTUN_HEADER_SIZE(pcb);
		uint32_t tx_length = kern_packet_get_data_length(tx_ph);
		if (tx_length < header_offset) {
			// Packet is too small
			kern_pbufpool_free(rx_pp, rx_ph);
			STATS_INC(nifs, NETIF_STATS_BADLEN);
			STATS_INC(nifs, NETIF_STATS_DROPPED);
			printf("utun_netif_sync_rx %s: packet length too short for header %u < %zu\n",
				   pcb->utun_ifp->if_xname, tx_length, header_offset);
			continue;
		}

		size_t length = MIN(tx_length - header_offset,
							UTUN_IF_DEFAULT_SLOT_SIZE);

		tx_ring_stats.kcrsi_slots_transferred++;
		tx_ring_stats.kcrsi_bytes_transferred += length;

		// Fillout rx packet
		kern_buflet_t rx_buf = kern_packet_get_next_buflet(rx_ph, NULL);
		VERIFY(rx_buf != NULL);
		void *rx_baddr = kern_buflet_get_object_address(rx_buf);
		VERIFY(rx_baddr != NULL);

		// Copy-in data from tx to rx
		memcpy((void *)rx_baddr, (void *)(tx_baddr + header_offset), length);
		kern_packet_clear_flow_uuid(rx_ph);	// Zero flow id

		// Finalize and attach the packet
		error = kern_buflet_set_data_offset(rx_buf, 0);
		VERIFY(error == 0);
		error = kern_buflet_set_data_length(rx_buf, length);
		VERIFY(error == 0);
		error = kern_packet_set_link_header_offset(rx_ph, 0);
		VERIFY(error == 0);
		error = kern_packet_set_network_header_offset(rx_ph, 0);
		VERIFY(error == 0);
		error = kern_packet_finalize(rx_ph);
		VERIFY(error == 0);
		error = kern_channel_slot_attach_packet(rx_ring, rx_slot, rx_ph);
		VERIFY(error == 0);

		STATS_INC(nifs, NETIF_STATS_RXPKTS);
		STATS_INC(nifs, NETIF_STATS_RXCOPY_DIRECT);
		bpf_tap_packet_in(pcb->utun_ifp, DLT_RAW, rx_ph, NULL, 0);

		rx_ring_stats.kcrsi_slots_transferred++;
		rx_ring_stats.kcrsi_bytes_transferred += length;

		rx_pslot = rx_slot;
		rx_slot = kern_channel_get_next_slot(rx_ring, rx_slot, NULL);
	}

done:
	if (rx_pslot) {
		kern_channel_advance_slot(rx_ring, rx_pslot);
		kern_channel_increment_ring_net_stats(rx_ring, pcb->utun_ifp, &rx_ring_stats);
	}

	if (tx_pslot) {
		kern_channel_advance_slot(tx_ring, tx_pslot);
		kern_channel_increment_ring_net_stats(tx_ring, pcb->utun_ifp, &tx_ring_stats);
		(void)kern_channel_reclaim(tx_ring);
	}

	// Unlock first, then exit ring
	lck_rw_unlock_shared(&pcb->utun_pcb_lock);
	if (tx_ring != NULL) {
		if (tx_pslot != NULL) {
			kern_channel_notify(tx_ring, 0);
		}
		kr_exit(tx_ring);
	}

	return 0;
}

static errno_t
utun_nexus_ifattach(struct utun_pcb *pcb,
					struct ifnet_init_eparams *init_params,
					struct ifnet **ifp)
{
	errno_t err;
	nexus_controller_t controller = kern_nexus_shared_controller();
	struct kern_nexus_net_init net_init;

	nexus_name_t provider_name;
	snprintf((char *)provider_name, sizeof(provider_name),
			 "com.apple.netif.utun%d", pcb->utun_unit);

	struct kern_nexus_provider_init prov_init = {
		.nxpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxpi_flags = NXPIF_VIRTUAL_DEVICE,
		.nxpi_pre_connect = utun_nexus_pre_connect,
		.nxpi_connected = utun_nexus_connected,
		.nxpi_pre_disconnect = utun_netif_pre_disconnect,
		.nxpi_disconnected = utun_nexus_disconnected,
		.nxpi_ring_init = utun_netif_ring_init,
		.nxpi_ring_fini = utun_netif_ring_fini,
		.nxpi_slot_init = NULL,
		.nxpi_slot_fini = NULL,
		.nxpi_sync_tx = utun_netif_sync_tx,
		.nxpi_sync_rx = utun_netif_sync_rx,
		.nxpi_tx_doorbell = utun_netif_tx_doorbell,
	};

	nexus_attr_t nxa = NULL;
	err = kern_nexus_attr_create(&nxa);
	if (err != 0) {
		printf("%s: kern_nexus_attr_create failed: %d\n",
			   __func__, err);
		goto failed;
	}

	uint64_t slot_buffer_size = UTUN_IF_DEFAULT_SLOT_SIZE;
	err = kern_nexus_attr_set(nxa, NEXUS_ATTR_SLOT_BUF_SIZE, slot_buffer_size);
	VERIFY(err == 0);

	// Reset ring size for netif nexus to limit memory usage
	uint64_t ring_size = if_utun_ring_size;
	err = kern_nexus_attr_set(nxa, NEXUS_ATTR_TX_SLOTS, ring_size);
	VERIFY(err == 0);
	err = kern_nexus_attr_set(nxa, NEXUS_ATTR_RX_SLOTS, ring_size);
	VERIFY(err == 0);

	pcb->utun_netif_txring_size = ring_size;

	err = kern_nexus_controller_register_provider(controller,
												  utun_nx_dom_prov,
												  provider_name,
												  &prov_init,
												  sizeof(prov_init),
												  nxa,
												  &pcb->utun_nx.if_provider);
	if (err != 0) {
		printf("%s register provider failed, error %d\n",
			   __func__, err);
		goto failed;
	}

	bzero(&net_init, sizeof(net_init));
	net_init.nxneti_version = KERN_NEXUS_NET_CURRENT_VERSION;
	net_init.nxneti_flags = 0;
	net_init.nxneti_eparams = init_params;
	net_init.nxneti_lladdr = NULL;
	net_init.nxneti_prepare = utun_netif_prepare;
	err = kern_nexus_controller_alloc_net_provider_instance(controller,
															pcb->utun_nx.if_provider,
															pcb,
															&pcb->utun_nx.if_instance,
															&net_init,
															ifp);
	if (err != 0) {
		printf("%s alloc_net_provider_instance failed, %d\n",
			   __func__, err);
		kern_nexus_controller_deregister_provider(controller,
												  pcb->utun_nx.if_provider);
		uuid_clear(pcb->utun_nx.if_provider);
		goto failed;
	}

failed:
	if (nxa) {
		kern_nexus_attr_destroy(nxa);
	}
	return (err);
}

static void
utun_detach_provider_and_instance(uuid_t provider, uuid_t instance)
{
	nexus_controller_t controller = kern_nexus_shared_controller();
	errno_t	err;

	if (!uuid_is_null(instance)) {
		err = kern_nexus_controller_free_provider_instance(controller,
														   instance);
		if (err != 0) {
			printf("%s free_provider_instance failed %d\n",
				   __func__, err);
		}
		uuid_clear(instance);
	}
	if (!uuid_is_null(provider)) {
		err = kern_nexus_controller_deregister_provider(controller,
														provider);
		if (err != 0) {
			printf("%s deregister_provider %d\n", __func__, err);
		}
		uuid_clear(provider);
	}
	return;
}

static void
utun_nexus_detach(utun_nx_t nx)
{
	nexus_controller_t controller = kern_nexus_shared_controller();
	errno_t	err;

	if (!uuid_is_null(nx->ms_host)) {
		err = kern_nexus_ifdetach(controller,
								  nx->ms_instance,
								  nx->ms_host);
		if (err != 0) {
			printf("%s: kern_nexus_ifdetach ms host failed %d\n",
				   __func__, err);
		}
	}

	if (!uuid_is_null(nx->ms_device)) {
		err = kern_nexus_ifdetach(controller,
								  nx->ms_instance,
								  nx->ms_device);
		if (err != 0) {
			printf("%s: kern_nexus_ifdetach ms device failed %d\n",
				   __func__, err);
		}
	}

	utun_detach_provider_and_instance(nx->if_provider,
									  nx->if_instance);
	utun_detach_provider_and_instance(nx->ms_provider,
									  nx->ms_instance);

	memset(nx, 0, sizeof(*nx));
}

static errno_t
utun_create_fs_provider_and_instance(uint32_t subtype, const char *type_name,
									 const char *ifname,
									 uuid_t *provider, uuid_t *instance)
{
	nexus_attr_t attr = NULL;
	nexus_controller_t controller = kern_nexus_shared_controller();
	uuid_t dom_prov;
	errno_t err;
	struct kern_nexus_init init;
	nexus_name_t	provider_name;

	err = kern_nexus_get_builtin_domain_provider(NEXUS_TYPE_FLOW_SWITCH,
												 &dom_prov);
	if (err != 0) {
		printf("%s can't get %s provider, error %d\n",
			   __func__, type_name, err);
		goto failed;
	}

	err = kern_nexus_attr_create(&attr);
	if (err != 0) {
		printf("%s: kern_nexus_attr_create failed: %d\n",
			   __func__, err);
		goto failed;
	}

	err = kern_nexus_attr_set(attr, NEXUS_ATTR_EXTENSIONS, subtype);
	VERIFY(err == 0);

	uint64_t slot_buffer_size = UTUN_IF_DEFAULT_SLOT_SIZE;
	err = kern_nexus_attr_set(attr, NEXUS_ATTR_SLOT_BUF_SIZE, slot_buffer_size);
	VERIFY(err == 0);

	// Reset ring size for flowswitch nexus to limit memory usage. Larger RX than netif.
	uint64_t tx_ring_size = if_utun_tx_fsw_ring_size;
	err = kern_nexus_attr_set(attr, NEXUS_ATTR_TX_SLOTS, tx_ring_size);
	VERIFY(err == 0);
	uint64_t rx_ring_size = if_utun_rx_fsw_ring_size;
	err = kern_nexus_attr_set(attr, NEXUS_ATTR_RX_SLOTS, rx_ring_size);
	VERIFY(err == 0);

	snprintf((char *)provider_name, sizeof(provider_name),
			 "com.apple.%s.%s", type_name, ifname);
	err = kern_nexus_controller_register_provider(controller,
												  dom_prov,
												  provider_name,
												  NULL,
												  0,
												  attr,
												  provider);
	kern_nexus_attr_destroy(attr);
	attr = NULL;
	if (err != 0) {
		printf("%s register %s provider failed, error %d\n",
			   __func__, type_name, err);
		goto failed;
	}
	bzero(&init, sizeof (init));
	init.nxi_version = KERN_NEXUS_CURRENT_VERSION;
	err = kern_nexus_controller_alloc_provider_instance(controller,
														*provider,
														NULL,
														instance, &init);
	if (err != 0) {
		printf("%s alloc_provider_instance %s failed, %d\n",
			   __func__, type_name, err);
		kern_nexus_controller_deregister_provider(controller,
												  *provider);
		uuid_clear(*provider);
	}
failed:
	return (err);
}

static errno_t
utun_multistack_attach(struct utun_pcb *pcb)
{
	nexus_controller_t controller = kern_nexus_shared_controller();
	errno_t err = 0;
	utun_nx_t nx = &pcb->utun_nx;

	// Allocate multistack flowswitch
	err = utun_create_fs_provider_and_instance(NEXUS_EXTENSION_FSW_TYPE_MULTISTACK,
											   "multistack",
											   pcb->utun_ifp->if_xname,
											   &nx->ms_provider,
											   &nx->ms_instance);
	if (err != 0) {
		printf("%s: failed to create bridge provider and instance\n",
			   __func__);
		goto failed;
	}

	// Attach multistack to device port
	err = kern_nexus_ifattach(controller, nx->ms_instance,
							  NULL, nx->if_instance,
							  FALSE, &nx->ms_device);
	if (err != 0) {
		printf("%s kern_nexus_ifattach ms device %d\n", __func__, err);
		goto failed;
	}

	// Attach multistack to host port
	err = kern_nexus_ifattach(controller, nx->ms_instance,
							  NULL, nx->if_instance,
							  TRUE, &nx->ms_host);
	if (err != 0) {
		printf("%s kern_nexus_ifattach ms host %d\n", __func__, err);
		goto failed;
	}

	// Extract the agent UUID and save for later
	struct kern_nexus *multistack_nx = nx_find(nx->ms_instance, false);
	if (multistack_nx != NULL) {
		struct nx_flowswitch *flowswitch = NX_FSW_PRIVATE(multistack_nx);
		if (flowswitch != NULL) {
			FSW_RLOCK(flowswitch);
			struct fsw_ms_context *ms_context = (struct fsw_ms_context *)flowswitch->fsw_ops_private;
			if (ms_context != NULL) {
				uuid_copy(nx->ms_agent, ms_context->mc_agent_uuid);
			} else {
				printf("utun_multistack_attach - fsw_ms_context is NULL\n");
			}
			FSW_UNLOCK(flowswitch);
		} else {
			printf("utun_multistack_attach - flowswitch is NULL\n");
		}
		nx_release(multistack_nx);
	} else {
		printf("utun_multistack_attach - unable to find multistack nexus\n");
	}

	return (0);

failed:
	utun_nexus_detach(nx);

	errno_t detach_error = 0;
	if ((detach_error = ifnet_detach(pcb->utun_ifp)) != 0) {
		panic("utun_multistack_attach - ifnet_detach failed: %d\n", detach_error);
		/* NOT REACHED */
	}
	
	return (err);
}

static errno_t
utun_register_kernel_pipe_nexus(void)
{
	nexus_attr_t nxa = NULL;
	errno_t result;

	lck_mtx_lock(&utun_lock);
	if (utun_ncd_refcount++) {
		lck_mtx_unlock(&utun_lock);
		return 0;
	}

	result = kern_nexus_controller_create(&utun_ncd);
	if (result) {
		printf("%s: kern_nexus_controller_create failed: %d\n",
			__FUNCTION__, result);
		goto done;
	}

	uuid_t dom_prov;
	result = kern_nexus_get_builtin_domain_provider(
		NEXUS_TYPE_KERNEL_PIPE, &dom_prov);
	if (result) {
		printf("%s: kern_nexus_get_builtin_domain_provider failed: %d\n",
			__FUNCTION__, result);
		goto done;
	}

	struct kern_nexus_provider_init prov_init = {
		.nxpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxpi_flags = NXPIF_VIRTUAL_DEVICE,
		.nxpi_pre_connect = utun_nexus_pre_connect,
		.nxpi_connected = utun_nexus_connected,
		.nxpi_pre_disconnect = utun_nexus_pre_disconnect,
		.nxpi_disconnected = utun_nexus_disconnected,
		.nxpi_ring_init = utun_kpipe_ring_init,
		.nxpi_ring_fini = utun_kpipe_ring_fini,
		.nxpi_slot_init = NULL,
		.nxpi_slot_fini = NULL,
		.nxpi_sync_tx = utun_kpipe_sync_tx,
		.nxpi_sync_rx = utun_kpipe_sync_rx,
		.nxpi_tx_doorbell = NULL,
	};

	result = kern_nexus_attr_create(&nxa);
	if (result) {
		printf("%s: kern_nexus_attr_create failed: %d\n",
			__FUNCTION__, result);
		goto done;
	}

	uint64_t slot_buffer_size = UTUN_IF_DEFAULT_SLOT_SIZE;
	result = kern_nexus_attr_set(nxa, NEXUS_ATTR_SLOT_BUF_SIZE, slot_buffer_size);
	VERIFY(result == 0);

	// Reset ring size for kernel pipe nexus to limit memory usage
	uint64_t ring_size = if_utun_ring_size;
	result = kern_nexus_attr_set(nxa, NEXUS_ATTR_TX_SLOTS, ring_size);
	VERIFY(result == 0);
	result = kern_nexus_attr_set(nxa, NEXUS_ATTR_RX_SLOTS, ring_size);
	VERIFY(result == 0);

	result = kern_nexus_controller_register_provider(utun_ncd,
													 dom_prov,
													 (const uint8_t *)"com.apple.nexus.utun.kpipe",
													 &prov_init,
													 sizeof(prov_init),
													 nxa,
													 &utun_kpipe_uuid);
	if (result) {
		printf("%s: kern_nexus_controller_register_provider failed: %d\n",
			__FUNCTION__, result);
		goto done;
	}

done:
	if (nxa) {
		kern_nexus_attr_destroy(nxa);
	}

	if (result) {
		if (utun_ncd) {
			kern_nexus_controller_destroy(utun_ncd);
			utun_ncd = NULL;
		}
		utun_ncd_refcount = 0;
	}

	lck_mtx_unlock(&utun_lock);

	return result;
}

static void
utun_unregister_kernel_pipe_nexus(void)
{
	lck_mtx_lock(&utun_lock);

	VERIFY(utun_ncd_refcount > 0);

	if (--utun_ncd_refcount == 0) {
		kern_nexus_controller_destroy(utun_ncd);
		utun_ncd = NULL;
	}

	lck_mtx_unlock(&utun_lock);
}

// For use by socket option, not internally
static errno_t
utun_disable_channel(struct utun_pcb *pcb)
{
	errno_t result;
	int enabled;
	uuid_t uuid;

	lck_rw_lock_exclusive(&pcb->utun_pcb_lock);

	enabled = pcb->utun_kpipe_enabled;
	uuid_copy(uuid, pcb->utun_kpipe_uuid);

	VERIFY(uuid_is_null(pcb->utun_kpipe_uuid) == !enabled);

	pcb->utun_kpipe_enabled = 0;
	uuid_clear(pcb->utun_kpipe_uuid);

	lck_rw_unlock_exclusive(&pcb->utun_pcb_lock);

	if (enabled) {
		result = kern_nexus_controller_free_provider_instance(utun_ncd, uuid);
	} else {
		result = ENXIO;
	}

	if (!result) {
		utun_unregister_kernel_pipe_nexus();
	}

	return result;
}

static errno_t
utun_enable_channel(struct utun_pcb *pcb, struct proc *proc)
{
	struct kern_nexus_init init;
	errno_t result;

	result = utun_register_kernel_pipe_nexus();
	if (result) {
		return result;
	}

	VERIFY(utun_ncd);

	lck_rw_lock_exclusive(&pcb->utun_pcb_lock);

	if (pcb->utun_kpipe_enabled) {
		result = EEXIST; // return success instead?
		goto done;
	}

	/*
	 * Make sure we can fit packets in the channel buffers and
	 * Allow an extra 4 bytes for the protocol number header in the channel
	 */
	if (pcb->utun_ifp->if_mtu + UTUN_HEADER_SIZE(pcb) > UTUN_IF_DEFAULT_SLOT_SIZE) {
		result = EOPNOTSUPP;
		goto done;
	}

	VERIFY(uuid_is_null(pcb->utun_kpipe_uuid));
	bzero(&init, sizeof (init));
	init.nxi_version = KERN_NEXUS_CURRENT_VERSION;
	result = kern_nexus_controller_alloc_provider_instance(utun_ncd,
		utun_kpipe_uuid, pcb, &pcb->utun_kpipe_uuid, &init);
	if (result) {
		goto done;
	}

	nexus_port_t port = NEXUS_PORT_KERNEL_PIPE_CLIENT;
	result = kern_nexus_controller_bind_provider_instance(utun_ncd,
		pcb->utun_kpipe_uuid, &port,
		proc_pid(proc), NULL, NULL, 0, NEXUS_BIND_PID);
	if (result) {
		kern_nexus_controller_free_provider_instance(utun_ncd,
			pcb->utun_kpipe_uuid);
		uuid_clear(pcb->utun_kpipe_uuid);
		goto done;
	}

	pcb->utun_kpipe_enabled = 1;

done:
	lck_rw_unlock_exclusive(&pcb->utun_pcb_lock);

	if (result) {
		utun_unregister_kernel_pipe_nexus();
	}

	return result;
}

#endif // UTUN_NEXUS

errno_t
utun_register_control(void)
{
	struct kern_ctl_reg kern_ctl;
	errno_t result = 0;
	
	/* Find a unique value for our interface family */
	result = mbuf_tag_id_find(UTUN_CONTROL_NAME, &utun_family);
	if (result != 0) {
		printf("utun_register_control - mbuf_tag_id_find_internal failed: %d\n", result);
		return result;
	}

	utun_pcb_size = sizeof(struct utun_pcb);
	utun_pcb_zone = zinit(utun_pcb_size,
						  UTUN_PCB_ZONE_MAX * utun_pcb_size,
						  0, UTUN_PCB_ZONE_NAME);
	if (utun_pcb_zone == NULL) {
		printf("utun_register_control - zinit(utun_pcb) failed");
		return ENOMEM;
	}

#if UTUN_NEXUS
	utun_register_nexus();
#endif // UTUN_NEXUS

	TAILQ_INIT(&utun_head);
	
	bzero(&kern_ctl, sizeof(kern_ctl));
	strlcpy(kern_ctl.ctl_name, UTUN_CONTROL_NAME, sizeof(kern_ctl.ctl_name));
	kern_ctl.ctl_name[sizeof(kern_ctl.ctl_name) - 1] = 0;
	kern_ctl.ctl_flags = CTL_FLAG_PRIVILEGED | CTL_FLAG_REG_EXTENDED; /* Require root */
	kern_ctl.ctl_sendsize = 512 * 1024;
	kern_ctl.ctl_recvsize = 512 * 1024;
	kern_ctl.ctl_connect = utun_ctl_connect;
	kern_ctl.ctl_disconnect = utun_ctl_disconnect;
	kern_ctl.ctl_send = utun_ctl_send;
	kern_ctl.ctl_setopt = utun_ctl_setopt;
	kern_ctl.ctl_getopt = utun_ctl_getopt;
	kern_ctl.ctl_rcvd = utun_ctl_rcvd;

	result = ctl_register(&kern_ctl, &utun_kctlref);
	if (result != 0) {
		printf("utun_register_control - ctl_register failed: %d\n", result);
		return result;
	}
	
	/* Register the protocol plumbers */
	if ((result = proto_register_plumber(PF_INET, utun_family,
										 utun_attach_proto, NULL)) != 0) {
		printf("utun_register_control - proto_register_plumber(PF_INET, %d) failed: %d\n",
			   utun_family, result);
		ctl_deregister(utun_kctlref);
		return result;
	}
	
	/* Register the protocol plumbers */
	if ((result = proto_register_plumber(PF_INET6, utun_family,
										 utun_attach_proto, NULL)) != 0) {
		proto_unregister_plumber(PF_INET, utun_family);
		ctl_deregister(utun_kctlref);
		printf("utun_register_control - proto_register_plumber(PF_INET6, %d) failed: %d\n",
			   utun_family, result);
		return result;
	}

	utun_lck_attr = lck_attr_alloc_init();
	utun_lck_grp_attr = lck_grp_attr_alloc_init();
	utun_lck_grp = lck_grp_alloc_init("utun",  utun_lck_grp_attr);

#if UTUN_NEXUS
	lck_mtx_init(&utun_lock, utun_lck_grp, utun_lck_attr);
#endif // UTUN_NEXUS

	return 0;
}

/* Kernel control functions */

static inline void
utun_free_pcb(struct utun_pcb *pcb)
{
#ifdef UTUN_NEXUS
	mbuf_freem_list(pcb->utun_input_chain);
	lck_mtx_destroy(&pcb->utun_input_chain_lock, utun_lck_grp);
#endif // UTUN_NEXUS
	lck_rw_destroy(&pcb->utun_pcb_lock, utun_lck_grp);
	lck_mtx_lock(&utun_lock);
	TAILQ_REMOVE(&utun_head, pcb, utun_chain);
	lck_mtx_unlock(&utun_lock);
	zfree(utun_pcb_zone, pcb);
}

static errno_t
utun_ctl_connect(kern_ctl_ref kctlref,
				 struct sockaddr_ctl *sac,
				 void **unitinfo)
{
	struct ifnet_init_eparams utun_init = {};
	errno_t result = 0;
	
	struct utun_pcb *pcb = zalloc(utun_pcb_zone);
	memset(pcb, 0, sizeof(*pcb));

	*unitinfo = pcb;
	pcb->utun_ctlref = kctlref;
	pcb->utun_unit = sac->sc_unit;
	pcb->utun_max_pending_packets = 1;

	lck_mtx_init(&pcb->utun_input_chain_lock, utun_lck_grp, utun_lck_attr);
	lck_rw_init(&pcb->utun_pcb_lock, utun_lck_grp, utun_lck_attr);

	lck_mtx_lock(&utun_lock);

	/* Find some open interface id */
	u_int32_t chosen_unique_id = 1;
	struct utun_pcb *next_pcb = TAILQ_LAST(&utun_head, utun_list);
	if (next_pcb != NULL) {
		/* List was not empty, add one to the last item */
		chosen_unique_id = next_pcb->utun_unique_id + 1;
		next_pcb = NULL;

		/*
		 * If this wrapped the id number, start looking at
		 * the front of the list for an unused id.
		 */
		if (chosen_unique_id == 0) {
			/* Find the next unused ID */
			chosen_unique_id = 1;
			TAILQ_FOREACH(next_pcb, &utun_head, utun_chain) {
				if (next_pcb->utun_unique_id > chosen_unique_id) {
					/* We found a gap */
					break;
				}

				chosen_unique_id = next_pcb->utun_unique_id + 1;
			}
		}
	}

	pcb->utun_unique_id = chosen_unique_id;

	if (next_pcb != NULL) {
		TAILQ_INSERT_BEFORE(next_pcb, pcb, utun_chain);
	} else {
		TAILQ_INSERT_TAIL(&utun_head, pcb, utun_chain);
	}
	lck_mtx_unlock(&utun_lock);

	snprintf(pcb->utun_if_xname, sizeof(pcb->utun_if_xname), "utun%d", pcb->utun_unit - 1);
	snprintf(pcb->utun_unique_name, sizeof(pcb->utun_unique_name), "utunid%d", pcb->utun_unique_id - 1);
	printf("utun_ctl_connect: creating interface %s (id %s)\n", pcb->utun_if_xname, pcb->utun_unique_name);

	/* Create the interface */
	bzero(&utun_init, sizeof(utun_init));
	utun_init.ver = IFNET_INIT_CURRENT_VERSION;
	utun_init.len = sizeof (utun_init);

#if UTUN_NEXUS
	utun_init.flags = (IFNET_INIT_SKYWALK_NATIVE | IFNET_INIT_NX_NOAUTO);
	utun_init.tx_headroom = UTUN_IF_HEADROOM_SIZE;
#else // UTUN_NEXUS
	utun_init.flags = IFNET_INIT_NX_NOAUTO;
	utun_init.start = utun_start;
	utun_init.framer_extended = utun_framer;
#endif // UTUN_NEXUS
	utun_init.name = "utun";
	utun_init.unit = pcb->utun_unit - 1;
	utun_init.uniqueid = pcb->utun_unique_name;
	utun_init.uniqueid_len = strlen(pcb->utun_unique_name);
	utun_init.family = utun_family;
	utun_init.subfamily = IFNET_SUBFAMILY_UTUN;
	utun_init.type = IFT_OTHER;
	utun_init.demux = utun_demux;
	utun_init.add_proto = utun_add_proto;
	utun_init.del_proto = utun_del_proto;
	utun_init.softc = pcb;
	utun_init.ioctl = utun_ioctl;
	utun_init.detach = utun_detached;

#if UTUN_NEXUS
	result = utun_nexus_ifattach(pcb, &utun_init, &pcb->utun_ifp);
	if (result != 0) {
		printf("utun_ctl_connect - utun_nexus_ifattach failed: %d\n", result);
		utun_free_pcb(pcb);
		*unitinfo = NULL;
		return result;
	}

	result = utun_multistack_attach(pcb);
	if (result != 0) {
		printf("utun_ctl_connect - utun_multistack_attach failed: %d\n", result);
		*unitinfo = NULL;
		return result;
	}

#else // UTUN_NEXUS
	/*
	 * Upon success, this holds an ifnet reference which we will
	 * release via ifnet_release() at final detach time.
	 */
	result = ifnet_allocate_extended(&utun_init, &pcb->utun_ifp);
	if (result != 0) {
		printf("utun_ctl_connect - ifnet_allocate failed: %d\n", result);
		utun_free_pcb(pcb);
		*unitinfo = NULL;
		return result;
	}
	
	/* Set flags and additional information. */
	ifnet_set_mtu(pcb->utun_ifp, UTUN_DEFAULT_MTU);
	ifnet_set_flags(pcb->utun_ifp, IFF_UP | IFF_MULTICAST | IFF_POINTOPOINT, 0xffff);

	/* The interface must generate its own IPv6 LinkLocal address,
	 * if possible following the recommendation of RFC2472 to the 64bit interface ID
	 */
	ifnet_set_eflags(pcb->utun_ifp, IFEF_NOAUTOIPV6LL, IFEF_NOAUTOIPV6LL);
	
	/* Reset the stats in case as the interface may have been recycled */
	struct ifnet_stats_param stats;
	bzero(&stats, sizeof(struct ifnet_stats_param));
	ifnet_set_stat(pcb->utun_ifp, &stats);

	/* Attach the interface */
	result = ifnet_attach(pcb->utun_ifp, NULL);
	if (result != 0) {
		printf("utun_ctl_connect - ifnet_attach failed: %d\n", result);
		/* Release reference now since attach failed */
		ifnet_release(pcb->utun_ifp);
		utun_free_pcb(pcb);
		*unitinfo = NULL;
		return (result);
	}
#endif // UTUN_NEXUS

	/* Attach to bpf */
	bpfattach(pcb->utun_ifp, DLT_RAW, 0);
	/* The interfaces resoures allocated, mark it as running */
	ifnet_set_flags(pcb->utun_ifp, IFF_RUNNING, IFF_RUNNING);

	return result;
}

static errno_t
utun_detach_ip(ifnet_t interface,
			   protocol_family_t protocol,
			   socket_t pf_socket)
{
	errno_t result = EPROTONOSUPPORT;
	
	/* Attempt a detach */
	if (protocol == PF_INET) {
		struct ifreq	ifr;
		
		bzero(&ifr, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d",
				 ifnet_name(interface), ifnet_unit(interface));
		
		result = sock_ioctl(pf_socket, SIOCPROTODETACH, &ifr);
	} else if (protocol == PF_INET6) {
		struct in6_ifreq	ifr6;
		
		bzero(&ifr6, sizeof(ifr6));
		snprintf(ifr6.ifr_name, sizeof(ifr6.ifr_name), "%s%d",
				 ifnet_name(interface), ifnet_unit(interface));
		
		result = sock_ioctl(pf_socket, SIOCPROTODETACH_IN6, &ifr6);
	}
	
	return result;
}

static void
utun_remove_address(ifnet_t interface,
					protocol_family_t protocol,
					ifaddr_t address,
					socket_t pf_socket)
{
	errno_t result = 0;
	
	/* Attempt a detach */
	if (protocol == PF_INET) {
		struct ifreq ifr;
		
		bzero(&ifr, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d",
				 ifnet_name(interface), ifnet_unit(interface));
		result = ifaddr_address(address, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
		if (result != 0) {
			printf("utun_remove_address - ifaddr_address failed: %d", result);
		} else {
			result = sock_ioctl(pf_socket, SIOCDIFADDR, &ifr);
			if (result != 0) {
				printf("utun_remove_address - SIOCDIFADDR failed: %d", result);
			}
		}
	} else if (protocol == PF_INET6) {
		struct in6_ifreq ifr6;
		
		bzero(&ifr6, sizeof(ifr6));
		snprintf(ifr6.ifr_name, sizeof(ifr6.ifr_name), "%s%d",
				 ifnet_name(interface), ifnet_unit(interface));
		result = ifaddr_address(address, (struct sockaddr*)&ifr6.ifr_addr,
								sizeof(ifr6.ifr_addr));
		if (result != 0) {
			printf("utun_remove_address - ifaddr_address failed (v6): %d",
				   result);
		} else {
			result = sock_ioctl(pf_socket, SIOCDIFADDR_IN6, &ifr6);
			if (result != 0) {
				printf("utun_remove_address - SIOCDIFADDR_IN6 failed: %d",
					   result);
			}
		}
	}
}

static void
utun_cleanup_family(ifnet_t interface,
					protocol_family_t protocol)
{
	errno_t result = 0;
	socket_t pf_socket = NULL;
	ifaddr_t *addresses = NULL;
	int i;
	
	if (protocol != PF_INET && protocol != PF_INET6) {
		printf("utun_cleanup_family - invalid protocol family %d\n", protocol);
		return;
	}
	
	/* Create a socket for removing addresses and detaching the protocol */
	result = sock_socket(protocol, SOCK_DGRAM, 0, NULL, NULL, &pf_socket);
	if (result != 0) {
		if (result != EAFNOSUPPORT)
			printf("utun_cleanup_family - failed to create %s socket: %d\n",
				protocol == PF_INET ? "IP" : "IPv6", result);
		goto cleanup;
	}
	
        /* always set SS_PRIV, we want to close and detach regardless */
        sock_setpriv(pf_socket, 1);

	result = utun_detach_ip(interface, protocol, pf_socket);
	if (result == 0 || result == ENXIO) {
		/* We are done! We either detached or weren't attached. */
		goto cleanup;
	} else if (result != EBUSY) {
		/* Uh, not really sure what happened here... */
		printf("utun_cleanup_family - utun_detach_ip failed: %d\n", result);
		goto cleanup;
	}
	
	/*
	 * At this point, we received an EBUSY error. This means there are
	 * addresses attached. We should detach them and then try again.
	 */
	result = ifnet_get_address_list_family(interface, &addresses, protocol);
	if (result != 0) {
		printf("fnet_get_address_list_family(%s%d, 0xblah, %s) - failed: %d\n",
			ifnet_name(interface), ifnet_unit(interface), 
			protocol == PF_INET ? "PF_INET" : "PF_INET6", result);
		goto cleanup;
	}
	
	for (i = 0; addresses[i] != 0; i++) {
		utun_remove_address(interface, protocol, addresses[i], pf_socket);
	}
	ifnet_free_address_list(addresses);
	addresses = NULL;
	
	/*
	 * The addresses should be gone, we should try the remove again.
	 */
	result = utun_detach_ip(interface, protocol, pf_socket);
	if (result != 0 && result != ENXIO) {
		printf("utun_cleanup_family - utun_detach_ip failed: %d\n", result);
	}
	
cleanup:
	if (pf_socket != NULL) {
		sock_close(pf_socket);
	}
	
	if (addresses != NULL) {
		ifnet_free_address_list(addresses);
	}
}

static errno_t
utun_ctl_disconnect(__unused kern_ctl_ref kctlref,
					__unused u_int32_t unit,
					void *unitinfo)
{
	struct utun_pcb	*pcb = unitinfo;
	ifnet_t ifp = NULL;
	errno_t result = 0;

	if (pcb == NULL) {
		return EINVAL;
	}

#if UTUN_NEXUS
	// Tell the nexus to stop all rings
	if (pcb->utun_netif_nexus != NULL) {
		kern_nexus_stop(pcb->utun_netif_nexus);
	}
#endif // UTUN_NEXUS

	lck_rw_lock_exclusive(&pcb->utun_pcb_lock);

#if UTUN_NEXUS
	uuid_t kpipe_uuid;
	uuid_copy(kpipe_uuid, pcb->utun_kpipe_uuid);
	uuid_clear(pcb->utun_kpipe_uuid);
	pcb->utun_kpipe_enabled = FALSE;
#endif // UTUN_NEXUS

	ifp = pcb->utun_ifp;
	VERIFY(ifp != NULL);
	pcb->utun_ctlref = NULL;

	/*
	 * Quiesce the interface and flush any pending outbound packets.
	 */
	if_down(ifp);

	/* Increment refcnt, but detach interface */
	ifnet_incr_iorefcnt(ifp);
	if ((result = ifnet_detach(ifp)) != 0) {
		panic("utun_ctl_disconnect - ifnet_detach failed: %d\n", result);
	}

	/*
	 * We want to do everything in our power to ensure that the interface
	 * really goes away when the socket is closed. We must remove IP/IPv6
	 * addresses and detach the protocols. Finally, we can remove and
	 * release the interface.
	 */
	utun_cleanup_family(ifp, AF_INET);
	utun_cleanup_family(ifp, AF_INET6);

	lck_rw_unlock_exclusive(&pcb->utun_pcb_lock);

#if UTUN_NEXUS
	if (!uuid_is_null(kpipe_uuid)) {
		if (kern_nexus_controller_free_provider_instance(utun_ncd, kpipe_uuid) == 0) {
			utun_unregister_kernel_pipe_nexus();
		}
	}
	utun_nexus_detach(&pcb->utun_nx);
#endif // UTUN_NEXUS

	/* Decrement refcnt to finish detaching and freeing */
	ifnet_decr_iorefcnt(ifp);
	
	return 0;
}

static errno_t
utun_ctl_send(__unused kern_ctl_ref kctlref,
			  __unused u_int32_t unit,
			  void *unitinfo,
			  mbuf_t m,
			  __unused int flags)
{
	/*
	 * The userland ABI requires the first four bytes have the protocol family 
	 * in network byte order: swap them
	 */
	if (m_pktlen(m) >= (int32_t)UTUN_HEADER_SIZE((struct utun_pcb *)unitinfo)) {
		*(protocol_family_t *)mbuf_data(m) = ntohl(*(protocol_family_t *)mbuf_data(m));
	} else {
		printf("%s - unexpected short mbuf pkt len %d\n", __func__, m_pktlen(m) );
	}

	return utun_pkt_input((struct utun_pcb *)unitinfo, m);
}

static errno_t
utun_ctl_setopt(__unused kern_ctl_ref kctlref,
				__unused u_int32_t unit,
				void *unitinfo,
				int opt,
				void *data,
				size_t len)
{
	struct utun_pcb *pcb = unitinfo;
	errno_t result = 0;
	/* check for privileges for privileged options */
	switch (opt) {
		case UTUN_OPT_FLAGS:
		case UTUN_OPT_EXT_IFDATA_STATS:
		case UTUN_OPT_SET_DELEGATE_INTERFACE:
			if (kauth_cred_issuser(kauth_cred_get()) == 0) {
				return EPERM;
			}
			break;
	}

	switch (opt) {
		case UTUN_OPT_FLAGS:
			if (len != sizeof(u_int32_t)) {
				result = EMSGSIZE;
			} else {
				pcb->utun_flags = *(u_int32_t *)data;
			}
			break;

		case UTUN_OPT_EXT_IFDATA_STATS:
			if (len != sizeof(int)) {
				result = EMSGSIZE;
				break;
			}
			pcb->utun_ext_ifdata_stats = (*(int *)data) ? 1 : 0;
			break;
			
		case UTUN_OPT_INC_IFDATA_STATS_IN:
		case UTUN_OPT_INC_IFDATA_STATS_OUT: {
			struct utun_stats_param *utsp = (struct utun_stats_param *)data;
			
			if (utsp == NULL || len < sizeof(struct utun_stats_param)) {
				result = EINVAL;
				break;
			}
			if (!pcb->utun_ext_ifdata_stats) {
				result = EINVAL;
				break;
			}
			if (opt == UTUN_OPT_INC_IFDATA_STATS_IN)
				ifnet_stat_increment_in(pcb->utun_ifp, utsp->utsp_packets, 
					utsp->utsp_bytes, utsp->utsp_errors);
			else
				ifnet_stat_increment_out(pcb->utun_ifp, utsp->utsp_packets, 
					utsp->utsp_bytes, utsp->utsp_errors);
			break;
		}
		case UTUN_OPT_SET_DELEGATE_INTERFACE: {
			ifnet_t		del_ifp = NULL;
			char            name[IFNAMSIZ];

			if (len > IFNAMSIZ - 1) {
				result = EMSGSIZE;
				break;
			}
			if (len != 0) {    /* if len==0, del_ifp will be NULL causing the delegate to be removed */
				bcopy(data, name, len);
				name[len] = 0;
				result = ifnet_find_by_name(name, &del_ifp);
			}
			if (result == 0) {
				result = ifnet_set_delegate(pcb->utun_ifp, del_ifp);
				if (del_ifp)
					ifnet_release(del_ifp);            
			}
			break;
		}
		case UTUN_OPT_MAX_PENDING_PACKETS: {
			u_int32_t max_pending_packets = 0;
			if (len != sizeof(u_int32_t)) {
				result = EMSGSIZE;
				break;
			}
			max_pending_packets = *(u_int32_t *)data;
			if (max_pending_packets == 0) {
				result = EINVAL;
				break;
			}
			pcb->utun_max_pending_packets = max_pending_packets;
			break;
		}
#if UTUN_NEXUS
		case UTUN_OPT_ENABLE_CHANNEL: {
			if (len != sizeof(int)) {
				result = EMSGSIZE;
				break;
			}
			if (*(int *)data) {
				result = utun_enable_channel(pcb, current_proc());
			} else {
				result = utun_disable_channel(pcb);
			}
			break;
		}
		case UTUN_OPT_ENABLE_FLOWSWITCH: {
			if (len != sizeof(int)) {
				result = EMSGSIZE;
				break;
			}
			if (!if_enable_netagent) {
				result = ENOTSUP;
				break;
			}
			if (uuid_is_null(pcb->utun_nx.ms_agent)) {
				result = ENOENT;
				break;
			}

			if (*(int *)data) {
				if_add_netagent(pcb->utun_ifp, pcb->utun_nx.ms_agent);
			} else {
				if_delete_netagent(pcb->utun_ifp, pcb->utun_nx.ms_agent);
			}
			break;
		}
#endif // UTUN_NEXUS
		default: {
			result = ENOPROTOOPT;
			break;
		}
	}

	return result;
}

static errno_t
utun_ctl_getopt(__unused kern_ctl_ref kctlref,
				__unused u_int32_t unit,
				void *unitinfo,
				int opt,
				void *data,
				size_t *len)
{
	struct utun_pcb *pcb = unitinfo;
	errno_t result = 0;
	
	switch (opt) {
		case UTUN_OPT_FLAGS:
			if (*len != sizeof(u_int32_t)) {
				result = EMSGSIZE;
			} else {
				*(u_int32_t *)data = pcb->utun_flags;
			}
			break;

		case UTUN_OPT_EXT_IFDATA_STATS:
			if (*len != sizeof(int)) {
				result = EMSGSIZE;
			} else {
				*(int *)data = (pcb->utun_ext_ifdata_stats) ? 1 : 0;
			}
			break;
		
		case UTUN_OPT_IFNAME:
			if (*len < MIN(strlen(pcb->utun_if_xname) + 1, sizeof(pcb->utun_if_xname))) {
				result = EMSGSIZE;
			} else {
				*len = snprintf(data, *len, "%s", pcb->utun_if_xname) + 1;
			}
			break;

		case UTUN_OPT_MAX_PENDING_PACKETS: {
			if (*len != sizeof(u_int32_t)) {
				result = EMSGSIZE;
			} else {
				*((u_int32_t *)data) = pcb->utun_max_pending_packets;
			}
			break;
		}

#if UTUN_NEXUS
		case UTUN_OPT_GET_CHANNEL_UUID:
			lck_rw_lock_shared(&pcb->utun_pcb_lock);
			if (uuid_is_null(pcb->utun_kpipe_uuid)) {
				result = ENXIO;
			} else if (*len != sizeof(uuid_t)) {
				result = EMSGSIZE;
			} else {
				uuid_copy(data, pcb->utun_kpipe_uuid);
			}
			lck_rw_unlock_shared(&pcb->utun_pcb_lock);
			break;
#endif // UTUN_NEXUS

		default:
			result = ENOPROTOOPT;
			break;
	}
	
	return result;
}

static void
utun_ctl_rcvd(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int flags)
{
#pragma unused(flags)
	bool reenable_output = false;
	struct utun_pcb *pcb = unitinfo;
	if (pcb == NULL) {
		return;
	}
	ifnet_lock_exclusive(pcb->utun_ifp);

	u_int32_t utun_packet_cnt;
	errno_t error_pc = ctl_getenqueuepacketcount(kctlref, unit, &utun_packet_cnt);
	if (error_pc != 0) {
		printf("utun_ctl_rcvd: ctl_getenqueuepacketcount returned error %d\n", error_pc);
		utun_packet_cnt = 0;
	}

	if (utun_packet_cnt < pcb->utun_max_pending_packets) {
		reenable_output = true;
	}

	if (reenable_output) {
		errno_t error = ifnet_enable_output(pcb->utun_ifp);
		if (error != 0) {
			printf("utun_ctl_rcvd: ifnet_enable_output returned error %d\n", error);
		}
	}
	ifnet_lock_done(pcb->utun_ifp);
}

/* Network Interface functions */
#if !UTUN_NEXUS
static void
utun_start(ifnet_t interface)
{
	mbuf_t data;
	struct utun_pcb *pcb = ifnet_softc(interface);

	VERIFY(pcb != NULL);

#if UTUN_NEXUS
	lck_rw_lock_shared(&pcb->utun_pcb_lock);
	if (pcb->utun_kpipe_enabled) {
		/* It's possible to have channels enabled, but not yet have the channel opened,
		 * in which case the rxring will not be set
		 */
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		if (pcb->utun_kpipe_rxring != NULL) {
			kern_channel_notify(pcb->utun_kpipe_rxring, 0);
		}
		return;
	}
	lck_rw_unlock_shared(&pcb->utun_pcb_lock);
#endif // UTUN_NEXUS

	for (;;) {
		bool can_accept_packets = true;
		ifnet_lock_shared(pcb->utun_ifp);

		u_int32_t utun_packet_cnt;
		errno_t error_pc = ctl_getenqueuepacketcount(pcb->utun_ctlref, pcb->utun_unit, &utun_packet_cnt);
		if (error_pc != 0) {
			printf("utun_start: ctl_getenqueuepacketcount returned error %d\n", error_pc);
			utun_packet_cnt = 0;
		}

		can_accept_packets = (utun_packet_cnt < pcb->utun_max_pending_packets);
		if (!can_accept_packets && pcb->utun_ctlref) {
			u_int32_t difference = 0;
			if (ctl_getenqueuereadable(pcb->utun_ctlref, pcb->utun_unit, &difference) == 0) {
				if (difference > 0) {
					// If the low-water mark has not yet been reached, we still need to enqueue data
					// into the buffer
					can_accept_packets = true;
				}
			}
		}
		if (!can_accept_packets) {
			errno_t error = ifnet_disable_output(interface);
			if (error != 0) {
				printf("utun_start: ifnet_disable_output returned error %d\n", error);
			}
			ifnet_lock_done(pcb->utun_ifp);
			break;
		}
		ifnet_lock_done(pcb->utun_ifp);
		if (ifnet_dequeue(interface, &data) != 0) {
			break;
		}
		if (utun_output(interface, data) != 0) {
			break;
		}
	}
}
#endif // !UTUN_NEXUS

static errno_t
utun_output(ifnet_t	interface,
			mbuf_t data)
{
	struct utun_pcb	*pcb = ifnet_softc(interface);
	errno_t result;

	VERIFY(interface == pcb->utun_ifp);

	if (pcb->utun_flags & UTUN_FLAGS_NO_OUTPUT) {
		/* flush data */
		mbuf_freem(data);
		return 0;
	}

	// otherwise, fall thru to ctl_enqueumbuf
	if (pcb->utun_ctlref) {
		int	length;

		/*
		 * The ABI requires the protocol in network byte order
		 */
		if (m_pktlen(data) >= (int32_t)UTUN_HEADER_SIZE(pcb)) {
			*(u_int32_t *)mbuf_data(data) = htonl(*(u_int32_t *)mbuf_data(data));
		}

		length = mbuf_pkthdr_len(data);
		result = ctl_enqueuembuf(pcb->utun_ctlref, pcb->utun_unit, data, CTL_DATA_EOR);
		if (result != 0) {
			mbuf_freem(data);
			printf("utun_output - ctl_enqueuembuf failed: %d\n", result);
#if !UTUN_NEXUS
			ifnet_stat_increment_out(interface, 0, 0, 1);
		} else {
			if (!pcb->utun_ext_ifdata_stats) {
				ifnet_stat_increment_out(interface, 1, length, 0);
			}
#endif // !UTUN_NEXUS
		}
	} else {
		mbuf_freem(data);
	}
	
	return 0;
}

static errno_t
utun_demux(__unused ifnet_t interface,
		   mbuf_t data,
		   __unused char *frame_header,
		   protocol_family_t *protocol)
{
	
	struct ip *ip;
	u_int ip_version;

	while (data != NULL && mbuf_len(data) < 1) {
		data = mbuf_next(data);
	}

	if (data == NULL)
		return ENOENT;

	ip = mtod(data, struct ip *);
	ip_version = ip->ip_v;

	switch(ip_version) {
		case 4:
			*protocol = PF_INET;
			return 0;
		case 6:
			*protocol = PF_INET6;
			return 0;
		default:
			*protocol = 0;
			break;
	}

	return 0;
}

#if !UTUN_NEXUS
static errno_t
utun_framer(ifnet_t interface,
			mbuf_t *packet,
			__unused const struct sockaddr *dest,
			__unused const char *desk_linkaddr,
			const char *frame_type,
			u_int32_t *prepend_len,
			u_int32_t *postpend_len)
{
	struct utun_pcb	*pcb = ifnet_softc(interface);
	VERIFY(interface == pcb->utun_ifp);

	u_int32_t header_length = UTUN_HEADER_SIZE(pcb);
    if (mbuf_prepend(packet, header_length, MBUF_DONTWAIT) != 0) {
		printf("utun_framer - ifnet_output prepend failed\n");

		ifnet_stat_increment_out(interface, 0, 0, 1);

		// just	return, because the buffer was freed in mbuf_prepend
        return EJUSTRETURN;	
    }
	if (prepend_len != NULL) {
		*prepend_len = header_length;
	}
	if (postpend_len != NULL) {
		*postpend_len = 0;
	}
	
    // place protocol number at the beginning of the mbuf
    *(protocol_family_t *)mbuf_data(*packet) = *(protocol_family_t *)(uintptr_t)(size_t)frame_type;


    return 0;
}
#endif // !UTUN_NEXUS

static errno_t
utun_add_proto(__unused ifnet_t interface,
			   protocol_family_t protocol,
			   __unused const struct ifnet_demux_desc *demux_array,
			   __unused u_int32_t demux_count)
{
	switch(protocol) {
		case PF_INET:
			return 0;
		case PF_INET6:
			return 0;
		default:
			break;
	}
	
	return ENOPROTOOPT;
}

static errno_t
utun_del_proto(__unused ifnet_t interface,
			   __unused protocol_family_t protocol)
{
	return 0;
}

static errno_t
utun_ioctl(ifnet_t interface,
		   u_long command,
		   void *data)
{
	errno_t	result = 0;
	
	switch(command) {
		case SIOCSIFMTU:
#if UTUN_NEXUS
		{
			// Make sure we can fit packets in the channel buffers
			// Allow for the headroom in the slot
			if (((uint64_t)((struct ifreq*)data)->ifr_mtu) + UTUN_IF_HEADROOM_SIZE > UTUN_IF_DEFAULT_SLOT_SIZE) {
				ifnet_set_mtu(interface, UTUN_IF_DEFAULT_SLOT_SIZE - UTUN_IF_HEADROOM_SIZE);
				break;
			}
		}
#endif // UTUN_NEXUS
			ifnet_set_mtu(interface, ((struct ifreq*)data)->ifr_mtu);
			break;
			
		case SIOCSIFFLAGS:
			/* ifioctl() takes care of it */
			break;
			
		default:
			result = EOPNOTSUPP;
	}
	
	return result;
}

static void
utun_detached(ifnet_t interface)
{
	struct utun_pcb	*pcb = ifnet_softc(interface);
	(void)ifnet_release(interface);
	utun_free_pcb(pcb);
}

/* Protocol Handlers */

static errno_t
utun_proto_input(__unused ifnet_t interface,
				 protocol_family_t protocol,
				 mbuf_t m,
				 __unused char *frame_header)
{
	if (proto_input(protocol, m) != 0) {
		m_freem(m);
#if !UTUN_NEXUS
		ifnet_stat_increment_in(interface, 0, 0, 1);
	} else {
		ifnet_stat_increment_in(interface, 1, m->m_pkthdr.len, 0);
#endif // UTUN_NEXUS
	}
	
	return 0;
}

static errno_t
utun_proto_pre_output(__unused ifnet_t interface,
					  protocol_family_t protocol,
					  __unused mbuf_t *packet,
					  __unused const struct sockaddr *dest,
					  __unused void *route,
					  char *frame_type,
					  __unused char *link_layer_dest)
{
	*(protocol_family_t *)(void *)frame_type = protocol;
	return 0;
}

static errno_t
utun_attach_proto(ifnet_t interface,
				  protocol_family_t protocol)
{
	struct ifnet_attach_proto_param	proto;
	
	bzero(&proto, sizeof(proto));
	proto.input = utun_proto_input;
	proto.pre_output = utun_proto_pre_output;

	errno_t result = ifnet_attach_protocol(interface, protocol, &proto);
	if (result != 0 && result != EEXIST) {
		printf("utun_attach_inet - ifnet_attach_protocol %d failed: %d\n",
			protocol, result);
	}
	
	return result;
}

#if UTUN_NEXUS
static errno_t
utun_pkt_input(struct utun_pcb *pcb, mbuf_t packet)
{
	lck_rw_lock_shared(&pcb->utun_pcb_lock);

	lck_mtx_lock(&pcb->utun_input_chain_lock);
	if (pcb->utun_input_chain != NULL) {
		pcb->utun_input_chain_last->m_nextpkt = packet;
	} else {
		pcb->utun_input_chain = packet;
	}
	while (packet->m_nextpkt) {
		VERIFY(packet != packet->m_nextpkt);
		packet = packet->m_nextpkt;
	}
	pcb->utun_input_chain_last = packet;
	lck_mtx_unlock(&pcb->utun_input_chain_lock);

	kern_channel_ring_t rx_ring = pcb->utun_netif_rxring;
	lck_rw_unlock_shared(&pcb->utun_pcb_lock);

	if (rx_ring != NULL) {
		kern_channel_notify(rx_ring, 0);
	}

	return (0);
}
#else
static errno_t
utun_pkt_input (struct utun_pcb *pcb, mbuf_t m)
{
	errno_t	result;
	protocol_family_t protocol = 0;

	mbuf_pkthdr_setrcvif(m, pcb->utun_ifp);

	if (m_pktlen(m) >= (int32_t)UTUN_HEADER_SIZE(pcb))  {
		protocol = *(u_int32_t *)mbuf_data(m);

		bpf_tap_in(pcb->utun_ifp, DLT_NULL, m, 0, 0);
	}
	if (pcb->utun_flags & UTUN_FLAGS_NO_INPUT) {
		/* flush data */
		mbuf_freem(m);
		return 0;
	}

	if (!pcb->utun_ext_ifdata_stats) {
		struct ifnet_stat_increment_param	incs;

		bzero(&incs, sizeof(incs));
		incs.packets_in = 1;
		incs.bytes_in = mbuf_pkthdr_len(m);
		result = ifnet_input(pcb->utun_ifp, m, &incs);
	} else {
		result = ifnet_input(pcb->utun_ifp, m, NULL);
	}
	if (result != 0) {
		ifnet_stat_increment_in(pcb->utun_ifp, 0, 0, 1);

		printf("%s - ifnet_input failed: %d\n", __FUNCTION__, result);
		mbuf_freem(m);
	}

	return 0;
}
#endif // UTUN_NEXUS


#if UTUN_NEXUS

static errno_t
utun_nxdp_init(__unused kern_nexus_domain_provider_t domprov)
{
	return 0;
}

static void
utun_nxdp_fini(__unused kern_nexus_domain_provider_t domprov)
{
	// Ignore
}

static errno_t
utun_register_nexus(void)
{
	const struct kern_nexus_domain_provider_init dp_init = {
		.nxdpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxdpi_flags = 0,
		.nxdpi_init = utun_nxdp_init,
		.nxdpi_fini = utun_nxdp_fini
	};
	errno_t err = 0;

	/* utun_nxdp_init() is called before this function returns */
	err = kern_nexus_register_domain_provider(NEXUS_TYPE_NET_IF,
											  (const uint8_t *) "com.apple.utun",
											  &dp_init, sizeof(dp_init),
											  &utun_nx_dom_prov);
	if (err != 0) {
		printf("%s: failed to register domain provider\n", __func__);
		return (err);
	}
	return (0);
}

static errno_t
utun_ifnet_set_attrs(ifnet_t ifp)
{
	/* Set flags and additional information. */
	ifnet_set_mtu(ifp, 1500);
	ifnet_set_flags(ifp, IFF_UP | IFF_MULTICAST | IFF_POINTOPOINT, 0xffff);

	/* The interface must generate its own IPv6 LinkLocal address,
	 * if possible following the recommendation of RFC2472 to the 64bit interface ID
	 */
	ifnet_set_eflags(ifp, IFEF_NOAUTOIPV6LL, IFEF_NOAUTOIPV6LL);

	return (0);
}

static errno_t
utun_netif_prepare(kern_nexus_t nexus, ifnet_t ifp)
{
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);
	pcb->utun_netif_nexus = nexus;
	return (utun_ifnet_set_attrs(ifp));
}

static errno_t
utun_nexus_pre_connect(kern_nexus_provider_t nxprov,
    proc_t p, kern_nexus_t nexus,
    nexus_port_t nexus_port, kern_channel_t channel, void **ch_ctx)
{
#pragma unused(nxprov, p)
#pragma unused(nexus, nexus_port, channel, ch_ctx)
	return (0);
}

static errno_t
utun_nexus_connected(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);
	boolean_t ok = ifnet_is_attached(pcb->utun_ifp, 1);
	return (ok ? 0 : ENXIO);
}

static void
utun_nexus_pre_disconnect(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov, nexus, channel)
}

static void
utun_netif_pre_disconnect(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
						  kern_channel_t channel)
{
#pragma unused(nxprov, nexus, channel)
}

static void
utun_nexus_disconnected(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);
	if (pcb->utun_netif_nexus == nexus) {
		pcb->utun_netif_nexus = NULL;
	}
	ifnet_decr_iorefcnt(pcb->utun_ifp);
}

static errno_t
utun_kpipe_ring_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
					 kern_channel_t channel, kern_channel_ring_t ring,
					 boolean_t is_tx_ring, void **ring_ctx)
{
#pragma unused(nxprov)
#pragma unused(channel)
#pragma unused(ring_ctx)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);
	if (!is_tx_ring) {
		VERIFY(pcb->utun_kpipe_rxring == NULL);
		pcb->utun_kpipe_rxring = ring;
	} else {
		VERIFY(pcb->utun_kpipe_txring == NULL);
		pcb->utun_kpipe_txring = ring;
	}
	return 0;
}

static void
utun_kpipe_ring_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
					 kern_channel_ring_t ring)
{
#pragma unused(nxprov)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);
	if (pcb->utun_kpipe_rxring == ring) {
		pcb->utun_kpipe_rxring = NULL;
	} else if (pcb->utun_kpipe_txring == ring) {
		pcb->utun_kpipe_txring = NULL;
	}
}

static errno_t
utun_kpipe_sync_tx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
				   kern_channel_ring_t tx_ring, uint32_t flags)
{
#pragma unused(nxprov)
#pragma unused(flags)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);

	lck_rw_lock_shared(&pcb->utun_pcb_lock);
	int channel_enabled = pcb->utun_kpipe_enabled;
	if (!channel_enabled) {
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		return 0;
	}

	kern_channel_slot_t tx_slot = kern_channel_get_next_slot(tx_ring, NULL, NULL);
	if (tx_slot == NULL) {
		// Nothing to write, bail
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		return 0;
	}

	// Signal the netif ring to read
	kern_channel_ring_t rx_ring = pcb->utun_netif_rxring;
	lck_rw_unlock_shared(&pcb->utun_pcb_lock);
	if (rx_ring != NULL) {
		kern_channel_notify(rx_ring, 0);
	}

	return 0;
}

static errno_t
utun_kpipe_sync_rx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
				   kern_channel_ring_t rx_ring, uint32_t flags)
{
#pragma unused(nxprov)
#pragma unused(flags)
	struct utun_pcb *pcb = kern_nexus_get_context(nexus);
	struct kern_channel_ring_stat_increment rx_ring_stats;

	lck_rw_lock_shared(&pcb->utun_pcb_lock);

	int channel_enabled = pcb->utun_kpipe_enabled;
	if (!channel_enabled) {
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		return 0;
	}

	/* reclaim user-released slots */
	(void) kern_channel_reclaim(rx_ring);

	uint32_t avail = kern_channel_available_slot_count(rx_ring);
	if (avail == 0) {
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		return 0;
	}

	kern_channel_ring_t tx_ring = pcb->utun_netif_txring;
	if (tx_ring == NULL ||
		pcb->utun_netif_nexus == NULL) {
		// Net-If TX ring not set up yet, nothing to read
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		return 0;
	}

	struct netif_stats *nifs = &NX_NETIF_PRIVATE(pcb->utun_netif_nexus)->nif_stats;

	// Unlock utun before entering ring
	lck_rw_unlock_shared(&pcb->utun_pcb_lock);

	(void)kr_enter(tx_ring, TRUE);

	// Lock again after entering and validate
	lck_rw_lock_shared(&pcb->utun_pcb_lock);
	if (tx_ring != pcb->utun_netif_txring) {
		// Ring no longer valid
		// Unlock first, then exit ring
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		kr_exit(tx_ring);
		return 0;
	}

	struct kern_channel_ring_stat_increment tx_ring_stats;
	bzero(&tx_ring_stats, sizeof(tx_ring_stats));
	kern_channel_slot_t tx_pslot = NULL;
	kern_channel_slot_t tx_slot = kern_channel_get_next_slot(tx_ring, NULL, NULL);
	if (tx_slot == NULL) {
		// Nothing to read, don't bother signalling
		// Unlock first, then exit ring
		lck_rw_unlock_shared(&pcb->utun_pcb_lock);
		kr_exit(tx_ring);
		return 0;
	}

	struct kern_pbufpool *rx_pp = rx_ring->ckr_pp;
	VERIFY(rx_pp != NULL);
	bzero(&rx_ring_stats, sizeof(rx_ring_stats));
	kern_channel_slot_t rx_pslot = NULL;
	kern_channel_slot_t rx_slot = kern_channel_get_next_slot(rx_ring, NULL, NULL);

	while (rx_slot != NULL && tx_slot != NULL) {
		size_t length;
		kern_buflet_t rx_buf;
		void *rx_baddr;

		kern_packet_t tx_ph = kern_channel_slot_get_packet(tx_ring, tx_slot);

		// Advance TX ring
		tx_pslot = tx_slot;
		tx_slot = kern_channel_get_next_slot(tx_ring, tx_slot, NULL);

		/* Skip slot if packet is zero-length or marked as dropped (QUMF_DROPPED) */
		if (tx_ph == 0) {
			continue;
		}

		// Allocate rx packet
		kern_packet_t rx_ph = 0;
		errno_t error = kern_pbufpool_alloc_nosleep(rx_pp, 1, &rx_ph);
		if (unlikely(error != 0)) {
			printf("utun_kpipe_sync_rx %s: failed to allocate packet\n",
				   pcb->utun_ifp->if_xname);
			break;
		}

		kern_buflet_t tx_buf = kern_packet_get_next_buflet(tx_ph, NULL);
		VERIFY(tx_buf != NULL);
		uint8_t *tx_baddr = kern_buflet_get_object_address(tx_buf);
		VERIFY(tx_baddr != NULL);
		tx_baddr += kern_buflet_get_data_offset(tx_buf);

		bpf_tap_packet_out(pcb->utun_ifp, DLT_RAW, tx_ph, NULL, 0);

		length = MIN(kern_packet_get_data_length(tx_ph) + UTUN_HEADER_SIZE(pcb),
					 UTUN_IF_DEFAULT_SLOT_SIZE);

		tx_ring_stats.kcrsi_slots_transferred++;
		tx_ring_stats.kcrsi_bytes_transferred += length;

		if (length < UTUN_HEADER_SIZE(pcb) ||
		    length > UTUN_IF_DEFAULT_SLOT_SIZE ||
		    length > rx_pp->pp_buflet_size ||
		    (pcb->utun_flags & UTUN_FLAGS_NO_OUTPUT)) {
			/* flush data */
			kern_pbufpool_free(rx_pp, rx_ph);
			printf("utun_kpipe_sync_rx %s: invalid length %zu header_size %zu\n",
				   pcb->utun_ifp->if_xname, length, UTUN_HEADER_SIZE(pcb));
			STATS_INC(nifs, NETIF_STATS_BADLEN);
			STATS_INC(nifs, NETIF_STATS_DROPPED);
			continue;
		}

		/* fillout packet */
		rx_buf = kern_packet_get_next_buflet(rx_ph, NULL);
		VERIFY(rx_buf != NULL);
		rx_baddr = kern_buflet_get_object_address(rx_buf);
		VERIFY(rx_baddr != NULL);

		// Find family
		uint32_t af = 0;
		uint8_t vhl = *(uint8_t *)(tx_baddr);
		u_int ip_version = (vhl >> 4);
		switch (ip_version) {
			case 4: {
				af = AF_INET;
				break;
			}
			case 6: {
				af = AF_INET6;
				break;
			}
			default: {
				printf("utun_kpipe_sync_rx %s: unknown ip version %u vhl %u header_size %zu\n",
					   pcb->utun_ifp->if_xname, ip_version, vhl, UTUN_HEADER_SIZE(pcb));
				break;
			}
		}

		// Copy header
		af = htonl(af);
		memcpy((void *)rx_baddr, &af, sizeof(af));
		if (pcb->utun_flags & UTUN_FLAGS_ENABLE_PROC_UUID) {
			kern_packet_get_euuid(tx_ph, (void *)(rx_baddr + sizeof(af)));
		}

		// Copy data from tx to rx
		memcpy((void *)(rx_baddr + UTUN_HEADER_SIZE(pcb)), (void *)tx_baddr, length - UTUN_HEADER_SIZE(pcb));
		kern_packet_clear_flow_uuid(rx_ph); // zero flow id

		/* finalize and attach the packet */
		error = kern_buflet_set_data_offset(rx_buf, 0);
		VERIFY(error == 0);
		error = kern_buflet_set_data_length(rx_buf, length);
		VERIFY(error == 0);
		error = kern_packet_finalize(rx_ph);
		VERIFY(error == 0);
		error = kern_channel_slot_attach_packet(rx_ring, rx_slot, rx_ph);
		VERIFY(error == 0);

		STATS_INC(nifs, NETIF_STATS_TXPKTS);
		STATS_INC(nifs, NETIF_STATS_TXCOPY_DIRECT);

		rx_ring_stats.kcrsi_slots_transferred++;
		rx_ring_stats.kcrsi_bytes_transferred += length;

		rx_pslot = rx_slot;
		rx_slot = kern_channel_get_next_slot(rx_ring, rx_slot, NULL);
	}

	if (rx_pslot) {
		kern_channel_advance_slot(rx_ring, rx_pslot);
		kern_channel_increment_ring_net_stats(rx_ring, pcb->utun_ifp, &rx_ring_stats);
	}

	if (tx_pslot) {
		kern_channel_advance_slot(tx_ring, tx_pslot);
		kern_channel_increment_ring_net_stats(tx_ring, pcb->utun_ifp, &tx_ring_stats);
		(void)kern_channel_reclaim(tx_ring);
	}

	if (pcb->utun_output_disabled) {
		errno_t error = ifnet_enable_output(pcb->utun_ifp);
		if (error != 0) {
			printf("utun_kpipe_sync_rx: ifnet_enable_output returned error %d\n", error);
		} else {
			pcb->utun_output_disabled = false;
		}
	}

	// Unlock first, then exit ring
	lck_rw_unlock_shared(&pcb->utun_pcb_lock);

	if (tx_pslot != NULL) {
		kern_channel_notify(tx_ring, 0);
	}
	kr_exit(tx_ring);

	return 0;
}

#endif // UTUN_NEXUS


/*
 * These are place holders until coreTLS kext stops calling them
 */
errno_t utun_ctl_register_dtls (void *reg);
int utun_pkt_dtls_input(struct utun_pcb *pcb, mbuf_t *pkt, protocol_family_t family);
void utun_ctl_disable_crypto_dtls(struct utun_pcb   *pcb);

errno_t
utun_ctl_register_dtls (void *reg)
{
#pragma unused(reg)
	return 0;
}

int
utun_pkt_dtls_input(struct utun_pcb *pcb, mbuf_t *pkt, protocol_family_t family)
{
#pragma unused(pcb)
#pragma unused(pkt)
#pragma unused(family)
	return 0;
}

void
utun_ctl_disable_crypto_dtls(struct utun_pcb   *pcb)
{
#pragma unused(pcb)
}
