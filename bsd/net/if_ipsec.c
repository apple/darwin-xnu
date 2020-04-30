/*
 * Copyright (c) 2012-2019 Apple Inc. All rights reserved.
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


#include <sys/systm.h>
#include <sys/kern_control.h>
#include <net/kpi_protocol.h>
#include <net/kpi_interface.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/if_ipsec.h>
#include <sys/mbuf.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <sys/kauth.h>
#include <netinet6/ipsec.h>
#include <netinet6/ipsec6.h>
#include <netinet6/esp.h>
#include <netinet6/esp6.h>
#include <netinet/ip.h>
#include <net/flowadv.h>
#include <net/necp.h>
#include <netkey/key.h>
#include <net/pktap.h>
#include <kern/zalloc.h>
#include <os/log.h>

#define IPSEC_NEXUS 0

extern int net_qos_policy_restricted;
extern int net_qos_policy_restrict_avapps;

/* Kernel Control functions */
static errno_t  ipsec_ctl_bind(kern_ctl_ref kctlref, struct sockaddr_ctl *sac,
    void **unitinfo);
static errno_t  ipsec_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac,
    void **unitinfo);
static errno_t  ipsec_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t unit,
    void *unitinfo);
static errno_t  ipsec_ctl_send(kern_ctl_ref kctlref, u_int32_t unit,
    void *unitinfo, mbuf_t m, int flags);
static errno_t  ipsec_ctl_getopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
    int opt, void *data, size_t *len);
static errno_t  ipsec_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
    int opt, void *data, size_t len);

/* Network Interface functions */
static void     ipsec_start(ifnet_t     interface);
static errno_t  ipsec_output(ifnet_t interface, mbuf_t data);
static errno_t  ipsec_demux(ifnet_t interface, mbuf_t data, char *frame_header,
    protocol_family_t *protocol);
static errno_t  ipsec_add_proto(ifnet_t interface, protocol_family_t protocol,
    const struct ifnet_demux_desc *demux_array,
    u_int32_t demux_count);
static errno_t  ipsec_del_proto(ifnet_t interface, protocol_family_t protocol);
static errno_t  ipsec_ioctl(ifnet_t interface, u_long cmd, void *data);
static void             ipsec_detached(ifnet_t interface);

/* Protocol handlers */
static errno_t  ipsec_attach_proto(ifnet_t interface, protocol_family_t proto);
static errno_t  ipsec_proto_input(ifnet_t interface, protocol_family_t protocol,
    mbuf_t m, char *frame_header);
static errno_t ipsec_proto_pre_output(ifnet_t interface, protocol_family_t protocol,
    mbuf_t *packet, const struct sockaddr *dest, void *route,
    char *frame_type, char *link_layer_dest);

static kern_ctl_ref     ipsec_kctlref;
static lck_attr_t *ipsec_lck_attr;
static lck_grp_attr_t *ipsec_lck_grp_attr;
static lck_grp_t *ipsec_lck_grp;
static lck_mtx_t ipsec_lock;

#if IPSEC_NEXUS

SYSCTL_DECL(_net_ipsec);
SYSCTL_NODE(_net, OID_AUTO, ipsec, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "IPsec");
static int if_ipsec_verify_interface_creation = 0;
SYSCTL_INT(_net_ipsec, OID_AUTO, verify_interface_creation, CTLFLAG_RW | CTLFLAG_LOCKED, &if_ipsec_verify_interface_creation, 0, "");

#define IPSEC_IF_VERIFY(_e)             if (__improbable(if_ipsec_verify_interface_creation)) { VERIFY(_e); }

#define IPSEC_IF_DEFAULT_SLOT_SIZE 2048
#define IPSEC_IF_DEFAULT_RING_SIZE 64
#define IPSEC_IF_DEFAULT_TX_FSW_RING_SIZE 64
#define IPSEC_IF_DEFAULT_RX_FSW_RING_SIZE 128
#define IPSEC_IF_DEFAULT_BUF_SEG_SIZE   skmem_usr_buf_seg_size

#define IPSEC_IF_WMM_RING_COUNT NEXUS_NUM_WMM_QUEUES
#define IPSEC_IF_MAX_RING_COUNT IPSEC_IF_WMM_RING_COUNT
#define IPSEC_NETIF_WMM_TX_RING_COUNT IPSEC_IF_WMM_RING_COUNT
#define IPSEC_NETIF_WMM_RX_RING_COUNT 1
#define IPSEC_NETIF_MAX_TX_RING_COUNT IPSEC_NETIF_WMM_TX_RING_COUNT
#define IPSEC_NETIF_MAX_RX_RING_COUNT IPSEC_NETIF_WMM_RX_RING_COUNT

#define IPSEC_IF_MIN_RING_SIZE 8
#define IPSEC_IF_MAX_RING_SIZE 1024

#define IPSEC_IF_MIN_SLOT_SIZE 1024
#define IPSEC_IF_MAX_SLOT_SIZE 4096

#define IPSEC_DEFAULT_MAX_PENDING_INPUT_COUNT 512

static int if_ipsec_max_pending_input = IPSEC_DEFAULT_MAX_PENDING_INPUT_COUNT;

static int sysctl_if_ipsec_ring_size SYSCTL_HANDLER_ARGS;
static int sysctl_if_ipsec_tx_fsw_ring_size SYSCTL_HANDLER_ARGS;
static int sysctl_if_ipsec_rx_fsw_ring_size SYSCTL_HANDLER_ARGS;

static int if_ipsec_ring_size = IPSEC_IF_DEFAULT_RING_SIZE;
static int if_ipsec_tx_fsw_ring_size = IPSEC_IF_DEFAULT_TX_FSW_RING_SIZE;
static int if_ipsec_rx_fsw_ring_size = IPSEC_IF_DEFAULT_RX_FSW_RING_SIZE;

SYSCTL_INT(_net_ipsec, OID_AUTO, max_pending_input, CTLFLAG_LOCKED | CTLFLAG_RW, &if_ipsec_max_pending_input, 0, "");
SYSCTL_PROC(_net_ipsec, OID_AUTO, ring_size, CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW,
    &if_ipsec_ring_size, IPSEC_IF_DEFAULT_RING_SIZE, &sysctl_if_ipsec_ring_size, "I", "");
SYSCTL_PROC(_net_ipsec, OID_AUTO, tx_fsw_ring_size, CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW,
    &if_ipsec_tx_fsw_ring_size, IPSEC_IF_DEFAULT_TX_FSW_RING_SIZE, &sysctl_if_ipsec_tx_fsw_ring_size, "I", "");
SYSCTL_PROC(_net_ipsec, OID_AUTO, rx_fsw_ring_size, CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW,
    &if_ipsec_rx_fsw_ring_size, IPSEC_IF_DEFAULT_RX_FSW_RING_SIZE, &sysctl_if_ipsec_rx_fsw_ring_size, "I", "");

static int if_ipsec_debug = 0;
SYSCTL_INT(_net_ipsec, OID_AUTO, debug, CTLFLAG_LOCKED | CTLFLAG_RW, &if_ipsec_debug, 0, "");

static errno_t
ipsec_register_nexus(void);

typedef struct ipsec_nx {
	uuid_t if_provider;
	uuid_t if_instance;
	uuid_t fsw_provider;
	uuid_t fsw_instance;
	uuid_t fsw_device;
	uuid_t fsw_host;
	uuid_t fsw_agent;
} *ipsec_nx_t;

static nexus_controller_t ipsec_ncd;
static int ipsec_ncd_refcount;
static uuid_t ipsec_kpipe_uuid;

#endif // IPSEC_NEXUS

/* Control block allocated for each kernel control connection */
struct ipsec_pcb {
	TAILQ_ENTRY(ipsec_pcb)  ipsec_chain;
	kern_ctl_ref            ipsec_ctlref;
	ifnet_t                 ipsec_ifp;
	u_int32_t               ipsec_unit;
	u_int32_t               ipsec_unique_id;
	// These external flags can be set with IPSEC_OPT_FLAGS
	u_int32_t               ipsec_external_flags;
	// These internal flags are only used within this driver
	u_int32_t               ipsec_internal_flags;
	u_int32_t               ipsec_input_frag_size;
	bool                    ipsec_frag_size_set;
	int                     ipsec_ext_ifdata_stats;
	mbuf_svc_class_t        ipsec_output_service_class;
	char                    ipsec_if_xname[IFXNAMSIZ];
	char                    ipsec_unique_name[IFXNAMSIZ];
	// PCB lock protects state fields, like ipsec_kpipe_count
	decl_lck_rw_data(, ipsec_pcb_lock);
	// lock to protect ipsec_pcb_data_move & ipsec_pcb_drainers
	decl_lck_mtx_data(, ipsec_pcb_data_move_lock);
	u_int32_t               ipsec_pcb_data_move; /* number of data moving contexts */
	u_int32_t               ipsec_pcb_drainers; /* number of threads waiting to drain */
	u_int32_t               ipsec_pcb_data_path_state; /* internal state of interface data path */

#if IPSEC_NEXUS
	lck_mtx_t               ipsec_input_chain_lock;
	lck_mtx_t               ipsec_kpipe_encrypt_lock;
	lck_mtx_t               ipsec_kpipe_decrypt_lock;
	struct mbuf *           ipsec_input_chain;
	struct mbuf *           ipsec_input_chain_last;
	u_int32_t               ipsec_input_chain_count;
	// Input chain lock protects the list of input mbufs
	// The input chain lock must be taken AFTER the PCB lock if both are held
	struct ipsec_nx         ipsec_nx;
	u_int32_t               ipsec_kpipe_count;
	pid_t                   ipsec_kpipe_pid;
	uuid_t                  ipsec_kpipe_uuid[IPSEC_IF_MAX_RING_COUNT];
	void *                  ipsec_kpipe_rxring[IPSEC_IF_MAX_RING_COUNT];
	void *                  ipsec_kpipe_txring[IPSEC_IF_MAX_RING_COUNT];
	kern_pbufpool_t         ipsec_kpipe_pp;
	u_int32_t               ipsec_kpipe_tx_ring_size;
	u_int32_t               ipsec_kpipe_rx_ring_size;

	kern_nexus_t            ipsec_netif_nexus;
	kern_pbufpool_t         ipsec_netif_pp;
	void *                  ipsec_netif_rxring[IPSEC_NETIF_MAX_RX_RING_COUNT];
	void *                  ipsec_netif_txring[IPSEC_NETIF_MAX_TX_RING_COUNT];
	uint64_t                ipsec_netif_txring_size;

	u_int32_t               ipsec_slot_size;
	u_int32_t               ipsec_netif_ring_size;
	u_int32_t               ipsec_tx_fsw_ring_size;
	u_int32_t               ipsec_rx_fsw_ring_size;
	bool                    ipsec_use_netif;
	bool                    ipsec_needs_netagent;
#endif // IPSEC_NEXUS
};

/* These are internal flags not exposed outside this file */
#define IPSEC_FLAGS_KPIPE_ALLOCATED 1

/* data movement refcounting functions */
static void ipsec_wait_data_move_drain(struct ipsec_pcb *pcb);

/* Data path states */
#define IPSEC_PCB_DATA_PATH_READY    0x1

/* Macros to set/clear/test data path states */
#define IPSEC_SET_DATA_PATH_READY(_pcb) ((_pcb)->ipsec_pcb_data_path_state |= IPSEC_PCB_DATA_PATH_READY)
#define IPSEC_CLR_DATA_PATH_READY(_pcb) ((_pcb)->ipsec_pcb_data_path_state &= ~IPSEC_PCB_DATA_PATH_READY)
#define IPSEC_IS_DATA_PATH_READY(_pcb) (((_pcb)->ipsec_pcb_data_path_state & IPSEC_PCB_DATA_PATH_READY) != 0)

#if IPSEC_NEXUS
/* Macros to clear/set/test flags. */
static inline void
ipsec_flag_set(struct ipsec_pcb *pcb, uint32_t flag)
{
	pcb->ipsec_internal_flags |= flag;
}
static inline void
ipsec_flag_clr(struct ipsec_pcb *pcb, uint32_t flag)
{
	pcb->ipsec_internal_flags &= ~flag;
}

static inline bool
ipsec_flag_isset(struct ipsec_pcb *pcb, uint32_t flag)
{
	return !!(pcb->ipsec_internal_flags & flag);
}
#endif // IPSEC_NEXUS

TAILQ_HEAD(ipsec_list, ipsec_pcb) ipsec_head;

#define IPSEC_PCB_ZONE_MAX              32
#define IPSEC_PCB_ZONE_NAME             "net.if_ipsec"

static unsigned int ipsec_pcb_size;             /* size of zone element */
static struct zone *ipsec_pcb_zone;             /* zone for ipsec_pcb */

#define IPSECQ_MAXLEN 256

#if IPSEC_NEXUS
static int
sysctl_if_ipsec_ring_size SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int value = if_ipsec_ring_size;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (value < IPSEC_IF_MIN_RING_SIZE ||
	    value > IPSEC_IF_MAX_RING_SIZE) {
		return EINVAL;
	}

	if_ipsec_ring_size = value;

	return 0;
}

static int
sysctl_if_ipsec_tx_fsw_ring_size SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int value = if_ipsec_tx_fsw_ring_size;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (value < IPSEC_IF_MIN_RING_SIZE ||
	    value > IPSEC_IF_MAX_RING_SIZE) {
		return EINVAL;
	}

	if_ipsec_tx_fsw_ring_size = value;

	return 0;
}

static int
sysctl_if_ipsec_rx_fsw_ring_size SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int value = if_ipsec_rx_fsw_ring_size;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (value < IPSEC_IF_MIN_RING_SIZE ||
	    value > IPSEC_IF_MAX_RING_SIZE) {
		return EINVAL;
	}

	if_ipsec_rx_fsw_ring_size = value;

	return 0;
}


static inline bool
ipsec_in_wmm_mode(struct ipsec_pcb *pcb)
{
	return pcb->ipsec_kpipe_count == IPSEC_IF_WMM_RING_COUNT;
}

#endif // IPSEC_NEXUS

errno_t
ipsec_register_control(void)
{
	struct kern_ctl_reg     kern_ctl;
	errno_t                         result = 0;

	ipsec_pcb_size = sizeof(struct ipsec_pcb);
	ipsec_pcb_zone = zinit(ipsec_pcb_size,
	    IPSEC_PCB_ZONE_MAX * ipsec_pcb_size,
	    0, IPSEC_PCB_ZONE_NAME);
	if (ipsec_pcb_zone == NULL) {
		os_log_error(OS_LOG_DEFAULT, "ipsec_register_control - zinit(ipsec_pcb) failed");
		return ENOMEM;
	}

#if IPSEC_NEXUS
	ipsec_register_nexus();
#endif // IPSEC_NEXUS

	TAILQ_INIT(&ipsec_head);

	bzero(&kern_ctl, sizeof(kern_ctl));
	strlcpy(kern_ctl.ctl_name, IPSEC_CONTROL_NAME, sizeof(kern_ctl.ctl_name));
	kern_ctl.ctl_name[sizeof(kern_ctl.ctl_name) - 1] = 0;
	kern_ctl.ctl_flags = CTL_FLAG_PRIVILEGED; /* Require root */
	kern_ctl.ctl_sendsize = 64 * 1024;
	kern_ctl.ctl_recvsize = 64 * 1024;
	kern_ctl.ctl_bind = ipsec_ctl_bind;
	kern_ctl.ctl_connect = ipsec_ctl_connect;
	kern_ctl.ctl_disconnect = ipsec_ctl_disconnect;
	kern_ctl.ctl_send = ipsec_ctl_send;
	kern_ctl.ctl_setopt = ipsec_ctl_setopt;
	kern_ctl.ctl_getopt = ipsec_ctl_getopt;

	result = ctl_register(&kern_ctl, &ipsec_kctlref);
	if (result != 0) {
		os_log_error(OS_LOG_DEFAULT, "ipsec_register_control - ctl_register failed: %d\n", result);
		return result;
	}

	/* Register the protocol plumbers */
	if ((result = proto_register_plumber(PF_INET, IFNET_FAMILY_IPSEC,
	    ipsec_attach_proto, NULL)) != 0) {
		os_log_error(OS_LOG_DEFAULT, "ipsec_register_control - proto_register_plumber(PF_INET, IFNET_FAMILY_IPSEC) failed: %d\n",
		    result);
		ctl_deregister(ipsec_kctlref);
		return result;
	}

	/* Register the protocol plumbers */
	if ((result = proto_register_plumber(PF_INET6, IFNET_FAMILY_IPSEC,
	    ipsec_attach_proto, NULL)) != 0) {
		proto_unregister_plumber(PF_INET, IFNET_FAMILY_IPSEC);
		ctl_deregister(ipsec_kctlref);
		os_log_error(OS_LOG_DEFAULT, "ipsec_register_control - proto_register_plumber(PF_INET6, IFNET_FAMILY_IPSEC) failed: %d\n",
		    result);
		return result;
	}

	ipsec_lck_attr = lck_attr_alloc_init();
	ipsec_lck_grp_attr = lck_grp_attr_alloc_init();
	ipsec_lck_grp = lck_grp_alloc_init("ipsec", ipsec_lck_grp_attr);
	lck_mtx_init(&ipsec_lock, ipsec_lck_grp, ipsec_lck_attr);

	return 0;
}

/* Helpers */
int
ipsec_interface_isvalid(ifnet_t interface)
{
	struct ipsec_pcb *pcb = NULL;

	if (interface == NULL) {
		return 0;
	}

	pcb = ifnet_softc(interface);

	if (pcb == NULL) {
		return 0;
	}

	/* When ctl disconnects, ipsec_unit is set to 0 */
	if (pcb->ipsec_unit == 0) {
		return 0;
	}

	return 1;
}

#if IPSEC_NEXUS
boolean_t
ipsec_interface_needs_netagent(ifnet_t interface)
{
	struct ipsec_pcb *pcb = NULL;

	if (interface == NULL) {
		return FALSE;
	}

	pcb = ifnet_softc(interface);

	if (pcb == NULL) {
		return FALSE;
	}

	return pcb->ipsec_needs_netagent == true;
}
#endif // IPSEC_NEXUS

static errno_t
ipsec_ifnet_set_attrs(ifnet_t ifp)
{
	/* Set flags and additional information. */
	ifnet_set_mtu(ifp, 1500);
	ifnet_set_flags(ifp, IFF_UP | IFF_MULTICAST | IFF_POINTOPOINT, 0xffff);

	/* The interface must generate its own IPv6 LinkLocal address,
	 * if possible following the recommendation of RFC2472 to the 64bit interface ID
	 */
	ifnet_set_eflags(ifp, IFEF_NOAUTOIPV6LL, IFEF_NOAUTOIPV6LL);

#if !IPSEC_NEXUS
	/* Reset the stats in case as the interface may have been recycled */
	struct ifnet_stats_param stats;
	bzero(&stats, sizeof(struct ifnet_stats_param));
	ifnet_set_stat(ifp, &stats);
#endif // !IPSEC_NEXUS

	return 0;
}

#if IPSEC_NEXUS

static uuid_t ipsec_nx_dom_prov;

static errno_t
ipsec_nxdp_init(__unused kern_nexus_domain_provider_t domprov)
{
	return 0;
}

static void
ipsec_nxdp_fini(__unused kern_nexus_domain_provider_t domprov)
{
	// Ignore
}

static errno_t
ipsec_register_nexus(void)
{
	const struct kern_nexus_domain_provider_init dp_init = {
		.nxdpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxdpi_flags = 0,
		.nxdpi_init = ipsec_nxdp_init,
		.nxdpi_fini = ipsec_nxdp_fini
	};
	errno_t err = 0;

	/* ipsec_nxdp_init() is called before this function returns */
	err = kern_nexus_register_domain_provider(NEXUS_TYPE_NET_IF,
	    (const uint8_t *) "com.apple.ipsec",
	    &dp_init, sizeof(dp_init),
	    &ipsec_nx_dom_prov);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s: failed to register domain provider\n", __func__);
		return err;
	}
	return 0;
}

static errno_t
ipsec_netif_prepare(kern_nexus_t nexus, ifnet_t ifp)
{
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);
	pcb->ipsec_netif_nexus = nexus;
	return ipsec_ifnet_set_attrs(ifp);
}

static errno_t
ipsec_nexus_pre_connect(kern_nexus_provider_t nxprov,
    proc_t p, kern_nexus_t nexus,
    nexus_port_t nexus_port, kern_channel_t channel, void **ch_ctx)
{
#pragma unused(nxprov, p)
#pragma unused(nexus, nexus_port, channel, ch_ctx)
	return 0;
}

static errno_t
ipsec_nexus_connected(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);
	boolean_t ok = ifnet_is_attached(pcb->ipsec_ifp, 1);
	/* Mark the data path as ready */
	if (ok) {
		lck_mtx_lock(&pcb->ipsec_pcb_data_move_lock);
		IPSEC_SET_DATA_PATH_READY(pcb);
		lck_mtx_unlock(&pcb->ipsec_pcb_data_move_lock);
	}
	return ok ? 0 : ENXIO;
}

static void
ipsec_nexus_pre_disconnect(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);

	VERIFY(pcb->ipsec_kpipe_count != 0);

	/* Wait until all threads in the data paths are done. */
	ipsec_wait_data_move_drain(pcb);
}

static void
ipsec_netif_pre_disconnect(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);

	/* Wait until all threads in the data paths are done. */
	ipsec_wait_data_move_drain(pcb);
}

static void
ipsec_nexus_disconnected(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);
	if (pcb->ipsec_netif_nexus == nexus) {
		pcb->ipsec_netif_nexus = NULL;
	}
	ifnet_decr_iorefcnt(pcb->ipsec_ifp);
}

static errno_t
ipsec_kpipe_ring_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel, kern_channel_ring_t ring, boolean_t is_tx_ring,
    void **ring_ctx)
{
#pragma unused(nxprov)
#pragma unused(channel)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);
	uint8_t ring_idx;

	for (ring_idx = 0; ring_idx < pcb->ipsec_kpipe_count; ring_idx++) {
		if (!uuid_compare(channel->ch_info->cinfo_nx_uuid, pcb->ipsec_kpipe_uuid[ring_idx])) {
			break;
		}
	}

	if (ring_idx == pcb->ipsec_kpipe_count) {
		uuid_string_t uuidstr;
		uuid_unparse(channel->ch_info->cinfo_nx_uuid, uuidstr);
		os_log_error(OS_LOG_DEFAULT, "%s: %s cannot find channel %s\n", __func__, pcb->ipsec_if_xname, uuidstr);
		return ENOENT;
	}

	*ring_ctx = (void *)(uintptr_t)ring_idx;

	if (!is_tx_ring) {
		VERIFY(pcb->ipsec_kpipe_rxring[ring_idx] == NULL);
		pcb->ipsec_kpipe_rxring[ring_idx] = ring;
	} else {
		VERIFY(pcb->ipsec_kpipe_txring[ring_idx] == NULL);
		pcb->ipsec_kpipe_txring[ring_idx] = ring;
	}
	return 0;
}

static void
ipsec_kpipe_ring_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring)
{
#pragma unused(nxprov)
	bool found = false;
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);

	for (unsigned int i = 0; i < pcb->ipsec_kpipe_count; i++) {
		if (pcb->ipsec_kpipe_rxring[i] == ring) {
			pcb->ipsec_kpipe_rxring[i] = NULL;
			found = true;
		} else if (pcb->ipsec_kpipe_txring[i] == ring) {
			pcb->ipsec_kpipe_txring[i] = NULL;
			found = true;
		}
	}
	VERIFY(found);
}

static errno_t
ipsec_kpipe_sync_tx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t tx_ring, uint32_t flags)
{
#pragma unused(nxprov)
#pragma unused(flags)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);

	if (!ipsec_data_move_begin(pcb)) {
		os_log_info(OS_LOG_DEFAULT, "%s: data path stopped for %s\n", __func__, if_name(pcb->ipsec_ifp));
		return 0;
	}

	lck_rw_lock_shared(&pcb->ipsec_pcb_lock);

	if (!ipsec_flag_isset(pcb, IPSEC_FLAGS_KPIPE_ALLOCATED)) {
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		ipsec_data_move_end(pcb);
		return 0;
	}

	VERIFY(pcb->ipsec_kpipe_count);

	kern_channel_slot_t tx_slot = kern_channel_get_next_slot(tx_ring, NULL, NULL);
	if (tx_slot == NULL) {
		// Nothing to write, bail
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		ipsec_data_move_end(pcb);
		return 0;
	}

	// Signal the netif ring to read
	kern_channel_ring_t rx_ring = pcb->ipsec_netif_rxring[0];
	lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);

	if (rx_ring != NULL) {
		kern_channel_notify(rx_ring, 0);
	}

	ipsec_data_move_end(pcb);
	return 0;
}

static mbuf_t
ipsec_encrypt_mbuf(ifnet_t interface,
    mbuf_t data)
{
	struct ipsec_output_state ipsec_state;
	int error = 0;
	uint32_t af;

	// Make sure this packet isn't looping through the interface
	if (necp_get_last_interface_index_from_packet(data) == interface->if_index) {
		error = -1;
		goto ipsec_output_err;
	}

	// Mark the interface so NECP can evaluate tunnel policy
	necp_mark_packet_from_interface(data, interface);

	struct ip *ip = mtod(data, struct ip *);
	u_int ip_version = ip->ip_v;

	switch (ip_version) {
	case 4: {
		af = AF_INET;

		memset(&ipsec_state, 0, sizeof(ipsec_state));
		ipsec_state.m = data;
		ipsec_state.dst = (struct sockaddr *)&ip->ip_dst;
		memset(&ipsec_state.ro, 0, sizeof(ipsec_state.ro));

		error = ipsec4_interface_output(&ipsec_state, interface);
		if (error == 0 && ipsec_state.tunneled == 6) {
			// Tunneled in IPv6 - packet is gone
			// TODO: Don't lose mbuf
			data = NULL;
			goto done;
		}

		data = ipsec_state.m;
		if (error || data == NULL) {
			if (error) {
				os_log_error(OS_LOG_DEFAULT, "ipsec_encrypt_mbuf: ipsec4_output error %d\n", error);
			}
			goto ipsec_output_err;
		}
		goto done;
	}
	case 6: {
		af = AF_INET6;

		data = ipsec6_splithdr(data);
		if (data == NULL) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_encrypt_mbuf: ipsec6_splithdr returned NULL\n");
			goto ipsec_output_err;
		}

		struct ip6_hdr *ip6 = mtod(data, struct ip6_hdr *);

		memset(&ipsec_state, 0, sizeof(ipsec_state));
		ipsec_state.m = data;
		ipsec_state.dst = (struct sockaddr *)&ip6->ip6_dst;
		memset(&ipsec_state.ro, 0, sizeof(ipsec_state.ro));

		error = ipsec6_interface_output(&ipsec_state, interface, &ip6->ip6_nxt, ipsec_state.m);
		if (error == 0 && ipsec_state.tunneled == 4) {
			// Tunneled in IPv4 - packet is gone
			// TODO: Don't lose mbuf
			data = NULL;
			goto done;
		}
		data = ipsec_state.m;
		if (error || data == NULL) {
			if (error) {
				os_log_error(OS_LOG_DEFAULT, "ipsec_encrypt_mbuf: ipsec6_output error %d\n", error);
			}
			goto ipsec_output_err;
		}
		goto done;
	}
	default: {
		os_log_error(OS_LOG_DEFAULT, "ipsec_encrypt_mbuf: Received unknown packet version %d\n", ip_version);
		error = -1;
		goto ipsec_output_err;
	}
	}

done:
	return data;

ipsec_output_err:
	if (data) {
		mbuf_freem(data);
	}
	return NULL;
}

static errno_t
ipsec_kpipe_sync_rx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t rx_ring, uint32_t flags)
{
#pragma unused(nxprov)
#pragma unused(flags)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);
	struct kern_channel_ring_stat_increment rx_ring_stats;
	uint8_t ring_idx = (uint8_t)(uintptr_t)kern_channel_ring_get_context(rx_ring);

	if (!ipsec_data_move_begin(pcb)) {
		os_log_error(OS_LOG_DEFAULT, "%s: data path stopped for %s\n", __func__, if_name(pcb->ipsec_ifp));
		return 0;
	}

	lck_rw_lock_shared(&pcb->ipsec_pcb_lock);

	if (!ipsec_flag_isset(pcb, IPSEC_FLAGS_KPIPE_ALLOCATED)) {
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		ipsec_data_move_end(pcb);
		return 0;
	}

	VERIFY(pcb->ipsec_kpipe_count);
	VERIFY(ring_idx <= pcb->ipsec_kpipe_count);

	// Reclaim user-released slots
	(void) kern_channel_reclaim(rx_ring);

	uint32_t avail = kern_channel_available_slot_count(rx_ring);
	if (avail == 0) {
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		os_log_error(OS_LOG_DEFAULT, "%s: %s ring %s index %d no room in rx_ring\n", __func__,
		    pcb->ipsec_if_xname, rx_ring->ckr_name, ring_idx);
		ipsec_data_move_end(pcb);
		return 0;
	}

	kern_channel_ring_t tx_ring = pcb->ipsec_netif_txring[ring_idx];
	if (tx_ring == NULL) {
		// Net-If TX ring not set up yet, nothing to read
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		os_log_error(OS_LOG_DEFAULT, "%s: %s ring %s index %d bad netif_txring 1\n", __func__,
		    pcb->ipsec_if_xname, rx_ring->ckr_name, ring_idx);
		ipsec_data_move_end(pcb);
		return 0;
	}

	struct netif_stats *nifs = &NX_NETIF_PRIVATE(pcb->ipsec_netif_nexus)->nif_stats;

	// Unlock ipsec before entering ring
	lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);

	(void)kr_enter(tx_ring, TRUE);

	// Lock again after entering and validate
	lck_rw_lock_shared(&pcb->ipsec_pcb_lock);
	if (tx_ring != pcb->ipsec_netif_txring[ring_idx]) {
		// Ring no longer valid
		// Unlock first, then exit ring
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		kr_exit(tx_ring);
		os_log_error(OS_LOG_DEFAULT, "%s: %s ring %s index %d bad netif_txring 2\n", __func__,
		    pcb->ipsec_if_xname, rx_ring->ckr_name, ring_idx);
		ipsec_data_move_end(pcb);
		return 0;
	}

	struct kern_channel_ring_stat_increment tx_ring_stats;
	bzero(&tx_ring_stats, sizeof(tx_ring_stats));
	kern_channel_slot_t tx_pslot = NULL;
	kern_channel_slot_t tx_slot = kern_channel_get_next_slot(tx_ring, NULL, NULL);
	if (tx_slot == NULL) {
		// Nothing to read, don't bother signalling
		// Unlock first, then exit ring
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		kr_exit(tx_ring);
		ipsec_data_move_end(pcb);
		return 0;
	}

	struct kern_pbufpool *rx_pp = rx_ring->ckr_pp;
	VERIFY(rx_pp != NULL);
	bzero(&rx_ring_stats, sizeof(rx_ring_stats));
	kern_channel_slot_t rx_pslot = NULL;
	kern_channel_slot_t rx_slot = kern_channel_get_next_slot(rx_ring, NULL, NULL);

	while (rx_slot != NULL && tx_slot != NULL) {
		size_t length = 0;
		mbuf_t data = NULL;
		errno_t error = 0;

		// Allocate rx packet
		kern_packet_t rx_ph = 0;
		error = kern_pbufpool_alloc_nosleep(rx_pp, 1, &rx_ph);
		if (__improbable(error != 0)) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_kpipe_sync_rx %s: failed to allocate packet\n",
			    pcb->ipsec_ifp->if_xname);
			break;
		}

		kern_packet_t tx_ph = kern_channel_slot_get_packet(tx_ring, tx_slot);

		// Advance TX ring
		tx_pslot = tx_slot;
		tx_slot = kern_channel_get_next_slot(tx_ring, tx_slot, NULL);

		if (tx_ph == 0) {
			kern_pbufpool_free(rx_pp, rx_ph);
			continue;
		}

		kern_buflet_t tx_buf = kern_packet_get_next_buflet(tx_ph, NULL);
		VERIFY(tx_buf != NULL);
		uint8_t *tx_baddr = kern_buflet_get_object_address(tx_buf);
		VERIFY(tx_baddr != NULL);
		tx_baddr += kern_buflet_get_data_offset(tx_buf);

		bpf_tap_packet_out(pcb->ipsec_ifp, DLT_RAW, tx_ph, NULL, 0);

		length = MIN(kern_packet_get_data_length(tx_ph),
		    pcb->ipsec_slot_size);

		// Increment TX stats
		tx_ring_stats.kcrsi_slots_transferred++;
		tx_ring_stats.kcrsi_bytes_transferred += length;

		if (length > 0) {
			error = mbuf_gethdr(MBUF_DONTWAIT, MBUF_TYPE_HEADER, &data);
			if (error == 0) {
				error = mbuf_copyback(data, 0, length, tx_baddr, MBUF_DONTWAIT);
				if (error == 0) {
					// Encrypt and send packet
					lck_mtx_lock(&pcb->ipsec_kpipe_encrypt_lock);
					data = ipsec_encrypt_mbuf(pcb->ipsec_ifp, data);
					lck_mtx_unlock(&pcb->ipsec_kpipe_encrypt_lock);
				} else {
					os_log_error(OS_LOG_DEFAULT, "ipsec_kpipe_sync_rx %s - mbuf_copyback(%zu) error %d\n", pcb->ipsec_ifp->if_xname, length, error);
					STATS_INC(nifs, NETIF_STATS_DROP_NOMEM_MBUF);
					STATS_INC(nifs, NETIF_STATS_DROP);
					mbuf_freem(data);
					data = NULL;
				}
			} else {
				os_log_error(OS_LOG_DEFAULT, "ipsec_kpipe_sync_rx %s - mbuf_gethdr error %d\n", pcb->ipsec_ifp->if_xname, error);
				STATS_INC(nifs, NETIF_STATS_DROP_NOMEM_MBUF);
				STATS_INC(nifs, NETIF_STATS_DROP);
			}
		} else {
			os_log_error(OS_LOG_DEFAULT, "ipsec_kpipe_sync_rx %s - 0 length packet\n", pcb->ipsec_ifp->if_xname);
			STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
			STATS_INC(nifs, NETIF_STATS_DROP);
		}

		if (data == NULL) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_kpipe_sync_rx %s: no encrypted packet to send\n", pcb->ipsec_ifp->if_xname);
			kern_pbufpool_free(rx_pp, rx_ph);
			break;
		}

		length = mbuf_pkthdr_len(data);
		if (length > rx_pp->pp_buflet_size) {
			// Flush data
			mbuf_freem(data);
			kern_pbufpool_free(rx_pp, rx_ph);
			os_log_error(OS_LOG_DEFAULT, "ipsec_kpipe_sync_rx %s: encrypted packet length %zu > %u\n",
			    pcb->ipsec_ifp->if_xname, length, rx_pp->pp_buflet_size);
			continue;
		}

		// Fillout rx packet
		kern_buflet_t rx_buf = kern_packet_get_next_buflet(rx_ph, NULL);
		VERIFY(rx_buf != NULL);
		void *rx_baddr = kern_buflet_get_object_address(rx_buf);
		VERIFY(rx_baddr != NULL);

		// Copy-in data from mbuf to buflet
		mbuf_copydata(data, 0, length, (void *)rx_baddr);
		kern_packet_clear_flow_uuid(rx_ph);     // Zero flow id

		// Finalize and attach the packet
		error = kern_buflet_set_data_offset(rx_buf, 0);
		VERIFY(error == 0);
		error = kern_buflet_set_data_length(rx_buf, length);
		VERIFY(error == 0);
		error = kern_packet_finalize(rx_ph);
		VERIFY(error == 0);
		error = kern_channel_slot_attach_packet(rx_ring, rx_slot, rx_ph);
		VERIFY(error == 0);

		STATS_INC(nifs, NETIF_STATS_TX_PACKETS);
		STATS_INC(nifs, NETIF_STATS_TX_COPY_DIRECT);

		rx_ring_stats.kcrsi_slots_transferred++;
		rx_ring_stats.kcrsi_bytes_transferred += length;

		if (!pcb->ipsec_ext_ifdata_stats) {
			ifnet_stat_increment_out(pcb->ipsec_ifp, 1, length, 0);
		}

		mbuf_freem(data);

		rx_pslot = rx_slot;
		rx_slot = kern_channel_get_next_slot(rx_ring, rx_slot, NULL);
	}

	if (rx_pslot) {
		kern_channel_advance_slot(rx_ring, rx_pslot);
		kern_channel_increment_ring_net_stats(rx_ring, pcb->ipsec_ifp, &rx_ring_stats);
	}

	if (tx_pslot) {
		kern_channel_advance_slot(tx_ring, tx_pslot);
		kern_channel_increment_ring_net_stats(tx_ring, pcb->ipsec_ifp, &tx_ring_stats);
		(void)kern_channel_reclaim(tx_ring);
	}

	/* always reenable output */
	errno_t error = ifnet_enable_output(pcb->ipsec_ifp);
	if (error != 0) {
		os_log_error(OS_LOG_DEFAULT, "ipsec_kpipe_sync_rx: ifnet_enable_output returned error %d\n", error);
	}

	// Unlock first, then exit ring
	lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);

	if (tx_pslot != NULL) {
		kern_channel_notify(tx_ring, 0);
	}
	kr_exit(tx_ring);

	ipsec_data_move_end(pcb);
	return 0;
}

static uint8_t
ipsec_find_tx_ring_by_svc(kern_packet_svc_class_t svc_class)
{
	switch (svc_class) {
	case KPKT_SC_VO: {
		return 0;
	}
	case KPKT_SC_VI: {
		return 1;
	}
	case KPKT_SC_BE: {
		return 2;
	}
	case KPKT_SC_BK: {
		return 3;
	}
	default: {
		VERIFY(0);
		return 0;
	}
	}
}

static errno_t
ipsec_netif_ring_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel, kern_channel_ring_t ring, boolean_t is_tx_ring,
    void **ring_ctx)
{
#pragma unused(nxprov)
#pragma unused(channel)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);

	if (!is_tx_ring) {
		VERIFY(pcb->ipsec_netif_rxring[0] == NULL);
		pcb->ipsec_netif_rxring[0] = ring;
	} else {
		uint8_t ring_idx = 0;
		if (ipsec_in_wmm_mode(pcb)) {
			int err;
			kern_packet_svc_class_t svc_class;
			err = kern_channel_get_service_class(ring, &svc_class);
			VERIFY(err == 0);
			ring_idx = ipsec_find_tx_ring_by_svc(svc_class);
			VERIFY(ring_idx < IPSEC_IF_WMM_RING_COUNT);
		}

		*ring_ctx = (void *)(uintptr_t)ring_idx;

		VERIFY(pcb->ipsec_netif_txring[ring_idx] == NULL);
		pcb->ipsec_netif_txring[ring_idx] = ring;
	}
	return 0;
}

static void
ipsec_netif_ring_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring)
{
#pragma unused(nxprov)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);
	bool found = false;

	for (int i = 0; i < IPSEC_NETIF_MAX_RX_RING_COUNT; i++) {
		if (pcb->ipsec_netif_rxring[i] == ring) {
			pcb->ipsec_netif_rxring[i] = NULL;
			VERIFY(!found);
			found = true;
		}
	}
	for (int i = 0; i < IPSEC_NETIF_MAX_TX_RING_COUNT; i++) {
		if (pcb->ipsec_netif_txring[i] == ring) {
			pcb->ipsec_netif_txring[i] = NULL;
			VERIFY(!found);
			found = true;
		}
	}
	VERIFY(found);
}

static bool
ipsec_netif_check_policy(mbuf_t data)
{
	necp_kernel_policy_result necp_result = 0;
	necp_kernel_policy_result_parameter necp_result_parameter = {};
	uint32_t necp_matched_policy_id = 0;

	// This packet has been marked with IP level policy, do not mark again.
	if (data && data->m_pkthdr.necp_mtag.necp_policy_id >= NECP_KERNEL_POLICY_ID_FIRST_VALID_IP) {
		return true;
	}

	size_t length = mbuf_pkthdr_len(data);
	if (length < sizeof(struct ip)) {
		return false;
	}

	struct ip *ip = mtod(data, struct ip *);
	u_int ip_version = ip->ip_v;
	switch (ip_version) {
	case 4: {
		necp_matched_policy_id = necp_ip_output_find_policy_match(data, 0, NULL, NULL,
		    &necp_result, &necp_result_parameter);
		break;
	}
	case 6: {
		necp_matched_policy_id = necp_ip6_output_find_policy_match(data, 0, NULL, NULL,
		    &necp_result, &necp_result_parameter);
		break;
	}
	default: {
		return false;
	}
	}

	if (necp_result == NECP_KERNEL_POLICY_RESULT_DROP ||
	    necp_result == NECP_KERNEL_POLICY_RESULT_SOCKET_DIVERT) {
		/* Drop and flow divert packets should be blocked at the IP layer */
		return false;
	}

	necp_mark_packet_from_ip(data, necp_matched_policy_id);
	return true;
}

static errno_t
ipsec_netif_sync_tx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t tx_ring, uint32_t flags)
{
#pragma unused(nxprov)
#pragma unused(flags)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);

	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;

	if (!ipsec_data_move_begin(pcb)) {
		os_log_error(OS_LOG_DEFAULT, "%s: data path stopped for %s\n", __func__, if_name(pcb->ipsec_ifp));
		return 0;
	}

	lck_rw_lock_shared(&pcb->ipsec_pcb_lock);

	struct kern_channel_ring_stat_increment tx_ring_stats;
	bzero(&tx_ring_stats, sizeof(tx_ring_stats));
	kern_channel_slot_t tx_pslot = NULL;
	kern_channel_slot_t tx_slot = kern_channel_get_next_slot(tx_ring, NULL, NULL);

	STATS_INC(nifs, NETIF_STATS_TX_SYNC);

	if (tx_slot == NULL) {
		// Nothing to write, don't bother signalling
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		ipsec_data_move_end(pcb);
		return 0;
	}

	if (pcb->ipsec_kpipe_count &&
	    ipsec_flag_isset(pcb, IPSEC_FLAGS_KPIPE_ALLOCATED)) {
		// Select the corresponding kpipe rx ring
		uint8_t ring_idx = (uint8_t)(uintptr_t)kern_channel_ring_get_context(tx_ring);
		VERIFY(ring_idx < IPSEC_IF_MAX_RING_COUNT);
		kern_channel_ring_t rx_ring = pcb->ipsec_kpipe_rxring[ring_idx];

		// Unlock while calling notify
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);

		// Signal the kernel pipe ring to read
		if (rx_ring != NULL) {
			kern_channel_notify(rx_ring, 0);
		}

		ipsec_data_move_end(pcb);
		return 0;
	}

	// If we're here, we're injecting into the BSD stack
	while (tx_slot != NULL) {
		size_t length = 0;
		mbuf_t data = NULL;

		kern_packet_t tx_ph = kern_channel_slot_get_packet(tx_ring, tx_slot);

		// Advance TX ring
		tx_pslot = tx_slot;
		tx_slot = kern_channel_get_next_slot(tx_ring, tx_slot, NULL);

		if (tx_ph == 0) {
			continue;
		}

		kern_buflet_t tx_buf = kern_packet_get_next_buflet(tx_ph, NULL);
		VERIFY(tx_buf != NULL);
		uint8_t *tx_baddr = kern_buflet_get_object_address(tx_buf);
		VERIFY(tx_baddr != 0);
		tx_baddr += kern_buflet_get_data_offset(tx_buf);

		bpf_tap_packet_out(pcb->ipsec_ifp, DLT_RAW, tx_ph, NULL, 0);

		length = MIN(kern_packet_get_data_length(tx_ph),
		    pcb->ipsec_slot_size);

		if (length > 0) {
			errno_t error = mbuf_gethdr(MBUF_DONTWAIT, MBUF_TYPE_HEADER, &data);
			if (error == 0) {
				error = mbuf_copyback(data, 0, length, tx_baddr, MBUF_DONTWAIT);
				if (error == 0) {
					// Mark packet from policy
					uint32_t policy_id = kern_packet_get_policy_id(tx_ph);
					necp_mark_packet_from_ip(data, policy_id);

					// Check policy with NECP
					if (!ipsec_netif_check_policy(data)) {
						os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_tx %s - failed policy check\n", pcb->ipsec_ifp->if_xname);
						STATS_INC(nifs, NETIF_STATS_DROP);
						mbuf_freem(data);
						data = NULL;
					} else {
						// Send through encryption
						error = ipsec_output(pcb->ipsec_ifp, data);
						if (error != 0) {
							os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_tx %s - ipsec_output error %d\n", pcb->ipsec_ifp->if_xname, error);
						}
					}
				} else {
					os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_tx %s - mbuf_copyback(%zu) error %d\n", pcb->ipsec_ifp->if_xname, length, error);
					STATS_INC(nifs, NETIF_STATS_DROP_NOMEM_MBUF);
					STATS_INC(nifs, NETIF_STATS_DROP);
					mbuf_freem(data);
					data = NULL;
				}
			} else {
				os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_tx %s - mbuf_gethdr error %d\n", pcb->ipsec_ifp->if_xname, error);
				STATS_INC(nifs, NETIF_STATS_DROP_NOMEM_MBUF);
				STATS_INC(nifs, NETIF_STATS_DROP);
			}
		} else {
			os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_tx %s - 0 length packet\n", pcb->ipsec_ifp->if_xname);
			STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
			STATS_INC(nifs, NETIF_STATS_DROP);
		}

		if (data == NULL) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_tx %s: no encrypted packet to send\n", pcb->ipsec_ifp->if_xname);
			break;
		}

		STATS_INC(nifs, NETIF_STATS_TX_PACKETS);
		STATS_INC(nifs, NETIF_STATS_TX_COPY_MBUF);

		tx_ring_stats.kcrsi_slots_transferred++;
		tx_ring_stats.kcrsi_bytes_transferred += length;
	}

	if (tx_pslot) {
		kern_channel_advance_slot(tx_ring, tx_pslot);
		kern_channel_increment_ring_net_stats(tx_ring, pcb->ipsec_ifp, &tx_ring_stats);
		(void)kern_channel_reclaim(tx_ring);
	}

	lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
	ipsec_data_move_end(pcb);

	return 0;
}

static errno_t
ipsec_netif_tx_doorbell_one(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, uint32_t flags, uint8_t ring_idx)
{
#pragma unused(nxprov)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);
	boolean_t more = false;
	errno_t rc = 0;

	VERIFY((flags & KERN_NEXUS_TXDOORBELLF_ASYNC_REFILL) == 0);

	/*
	 * Refill and sync the ring; we may be racing against another thread doing
	 * an RX sync that also wants to do kr_enter(), and so use the blocking
	 * variant here.
	 */
	rc = kern_channel_tx_refill_canblock(ring, UINT32_MAX, UINT32_MAX, true, &more);
	if (rc != 0 && rc != EAGAIN && rc != EBUSY) {
		os_log_error(OS_LOG_DEFAULT, "%s: %s ring %s tx refill failed %d\n", __func__,
		    pcb->ipsec_if_xname, ring->ckr_name, rc);
	}

	(void) kr_enter(ring, TRUE);
	lck_rw_lock_shared(&pcb->ipsec_pcb_lock);
	if (ring != pcb->ipsec_netif_txring[ring_idx]) {
		// ring no longer valid
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		kr_exit(ring);
		os_log_error(OS_LOG_DEFAULT, "%s: %s ring %s index %d bad netif_txring 3\n", __func__,
		    pcb->ipsec_if_xname, ring->ckr_name, ring_idx);
		return ENXIO;
	}

	if (pcb->ipsec_kpipe_count) {
		uint32_t tx_available = kern_channel_available_slot_count(ring);
		if (pcb->ipsec_netif_txring_size > 0 &&
		    tx_available >= pcb->ipsec_netif_txring_size - 1) {
			// No room left in tx ring, disable output for now
			errno_t error = ifnet_disable_output(pcb->ipsec_ifp);
			if (error != 0) {
				os_log_error(OS_LOG_DEFAULT, "ipsec_netif_tx_doorbell: ifnet_disable_output returned error %d\n", error);
			}
		}
	}

	if (pcb->ipsec_kpipe_count) {
		kern_channel_ring_t rx_ring = pcb->ipsec_kpipe_rxring[ring_idx];

		// Unlock while calling notify
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		// Signal the kernel pipe ring to read
		if (rx_ring != NULL) {
			kern_channel_notify(rx_ring, 0);
		}
	} else {
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
	}

	kr_exit(ring);

	return 0;
}

static errno_t
ipsec_netif_tx_doorbell(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, __unused uint32_t flags)
{
	errno_t ret = 0;
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);

	if (!ipsec_data_move_begin(pcb)) {
		os_log_error(OS_LOG_DEFAULT, "%s: data path stopped for %s\n", __func__, if_name(pcb->ipsec_ifp));
		return 0;
	}

	if (ipsec_in_wmm_mode(pcb)) {
		for (uint8_t i = 0; i < IPSEC_IF_WMM_RING_COUNT; i++) {
			kern_channel_ring_t nring = pcb->ipsec_netif_txring[i];
			ret = ipsec_netif_tx_doorbell_one(nxprov, nexus, nring, flags, i);
			if (ret) {
				break;
			}
		}
	} else {
		ret = ipsec_netif_tx_doorbell_one(nxprov, nexus, ring, flags, 0);
	}

	ipsec_data_move_end(pcb);
	return ret;
}

static errno_t
ipsec_netif_sync_rx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t rx_ring, uint32_t flags)
{
#pragma unused(nxprov)
#pragma unused(flags)
	struct ipsec_pcb *pcb = kern_nexus_get_context(nexus);
	struct kern_channel_ring_stat_increment rx_ring_stats;

	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;

	if (!ipsec_data_move_begin(pcb)) {
		os_log_error(OS_LOG_DEFAULT, "%s: data path stopped for %s\n", __func__, if_name(pcb->ipsec_ifp));
		return 0;
	}

	lck_rw_lock_shared(&pcb->ipsec_pcb_lock);

	// Reclaim user-released slots
	(void) kern_channel_reclaim(rx_ring);

	STATS_INC(nifs, NETIF_STATS_RX_SYNC);

	uint32_t avail = kern_channel_available_slot_count(rx_ring);
	if (avail == 0) {
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		ipsec_data_move_end(pcb);
		return 0;
	}

	struct kern_pbufpool *rx_pp = rx_ring->ckr_pp;
	VERIFY(rx_pp != NULL);
	bzero(&rx_ring_stats, sizeof(rx_ring_stats));
	kern_channel_slot_t rx_pslot = NULL;
	kern_channel_slot_t rx_slot = kern_channel_get_next_slot(rx_ring, NULL, NULL);

	while (rx_slot != NULL) {
		// Check for a waiting packet
		lck_mtx_lock(&pcb->ipsec_input_chain_lock);
		mbuf_t data = pcb->ipsec_input_chain;
		if (data == NULL) {
			lck_mtx_unlock(&pcb->ipsec_input_chain_lock);
			break;
		}

		// Allocate rx packet
		kern_packet_t rx_ph = 0;
		errno_t error = kern_pbufpool_alloc_nosleep(rx_pp, 1, &rx_ph);
		if (__improbable(error != 0)) {
			STATS_INC(nifs, NETIF_STATS_DROP_NOMEM_PKT);
			STATS_INC(nifs, NETIF_STATS_DROP);
			lck_mtx_unlock(&pcb->ipsec_input_chain_lock);
			break;
		}

		// Advance waiting packets
		if (pcb->ipsec_input_chain_count > 0) {
			pcb->ipsec_input_chain_count--;
		}
		pcb->ipsec_input_chain = data->m_nextpkt;
		data->m_nextpkt = NULL;
		if (pcb->ipsec_input_chain == NULL) {
			pcb->ipsec_input_chain_last = NULL;
		}
		lck_mtx_unlock(&pcb->ipsec_input_chain_lock);

		size_t length = mbuf_pkthdr_len(data);

		if (length < sizeof(struct ip)) {
			// Flush data
			mbuf_freem(data);
			kern_pbufpool_free(rx_pp, rx_ph);
			STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
			STATS_INC(nifs, NETIF_STATS_DROP);
			os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: legacy decrypted packet length cannot hold IP %zu < %zu\n",
			    pcb->ipsec_ifp->if_xname, length, sizeof(struct ip));
			continue;
		}

		uint32_t af = 0;
		struct ip *ip = mtod(data, struct ip *);
		u_int ip_version = ip->ip_v;
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
			os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: legacy unknown ip version %u\n",
			    pcb->ipsec_ifp->if_xname, ip_version);
			break;
		}
		}

		if (length > rx_pp->pp_buflet_size ||
		    (pcb->ipsec_frag_size_set && length > pcb->ipsec_input_frag_size)) {
			// We need to fragment to send up into the netif

			u_int32_t fragment_mtu = rx_pp->pp_buflet_size;
			if (pcb->ipsec_frag_size_set &&
			    pcb->ipsec_input_frag_size < rx_pp->pp_buflet_size) {
				fragment_mtu = pcb->ipsec_input_frag_size;
			}

			mbuf_t fragment_chain = NULL;
			switch (af) {
			case AF_INET: {
				// ip_fragment expects the length in host order
				ip->ip_len = ntohs(ip->ip_len);

				// ip_fragment will modify the original data, don't free
				int fragment_error = ip_fragment(data, pcb->ipsec_ifp, fragment_mtu, TRUE);
				if (fragment_error == 0 && data != NULL) {
					fragment_chain = data;
				} else {
					STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
					STATS_INC(nifs, NETIF_STATS_DROP);
					os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: failed to fragment IPv4 packet of length %zu (%d)\n",
					    pcb->ipsec_ifp->if_xname, length, fragment_error);
				}
				break;
			}
			case AF_INET6: {
				if (length < sizeof(struct ip6_hdr)) {
					mbuf_freem(data);
					STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
					STATS_INC(nifs, NETIF_STATS_DROP);
					os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: failed to fragment IPv6 packet of length %zu < %zu\n",
					    pcb->ipsec_ifp->if_xname, length, sizeof(struct ip6_hdr));
				} else {
					// ip6_do_fragmentation will free the original data on success only
					struct ip6_hdr *ip6 = mtod(data, struct ip6_hdr *);

					int fragment_error = ip6_do_fragmentation(&data, 0, pcb->ipsec_ifp, sizeof(struct ip6_hdr),
					    ip6, NULL, fragment_mtu, ip6->ip6_nxt, htonl(ip6_randomid()));
					if (fragment_error == 0 && data != NULL) {
						fragment_chain = data;
					} else {
						mbuf_freem(data);
						STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
						STATS_INC(nifs, NETIF_STATS_DROP);
						os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: failed to fragment IPv6 packet of length %zu (%d)\n",
						    pcb->ipsec_ifp->if_xname, length, fragment_error);
					}
				}
				break;
			}
			default: {
				// Cannot fragment unknown families
				mbuf_freem(data);
				STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
				STATS_INC(nifs, NETIF_STATS_DROP);
				os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: uknown legacy decrypted packet length %zu > %u\n",
				    pcb->ipsec_ifp->if_xname, length, rx_pp->pp_buflet_size);
				break;
			}
			}

			if (fragment_chain != NULL) {
				// Add fragments to chain before continuing
				lck_mtx_lock(&pcb->ipsec_input_chain_lock);
				if (pcb->ipsec_input_chain != NULL) {
					pcb->ipsec_input_chain_last->m_nextpkt = fragment_chain;
				} else {
					pcb->ipsec_input_chain = fragment_chain;
				}
				pcb->ipsec_input_chain_count++;
				while (fragment_chain->m_nextpkt) {
					VERIFY(fragment_chain != fragment_chain->m_nextpkt);
					fragment_chain = fragment_chain->m_nextpkt;
					pcb->ipsec_input_chain_count++;
				}
				pcb->ipsec_input_chain_last = fragment_chain;
				lck_mtx_unlock(&pcb->ipsec_input_chain_lock);
			}

			// Make sure to free unused rx packet
			kern_pbufpool_free(rx_pp, rx_ph);

			continue;
		}

		mbuf_pkthdr_setrcvif(data, pcb->ipsec_ifp);

		// Fillout rx packet
		kern_buflet_t rx_buf = kern_packet_get_next_buflet(rx_ph, NULL);
		VERIFY(rx_buf != NULL);
		void *rx_baddr = kern_buflet_get_object_address(rx_buf);
		VERIFY(rx_baddr != NULL);

		// Copy-in data from mbuf to buflet
		mbuf_copydata(data, 0, length, (void *)rx_baddr);
		kern_packet_clear_flow_uuid(rx_ph);     // Zero flow id

		// Finalize and attach the packet
		error = kern_buflet_set_data_offset(rx_buf, 0);
		VERIFY(error == 0);
		error = kern_buflet_set_data_length(rx_buf, length);
		VERIFY(error == 0);
		error = kern_packet_set_headroom(rx_ph, 0);
		VERIFY(error == 0);
		error = kern_packet_finalize(rx_ph);
		VERIFY(error == 0);
		error = kern_channel_slot_attach_packet(rx_ring, rx_slot, rx_ph);
		VERIFY(error == 0);

		STATS_INC(nifs, NETIF_STATS_RX_PACKETS);
		STATS_INC(nifs, NETIF_STATS_RX_COPY_MBUF);
		bpf_tap_packet_in(pcb->ipsec_ifp, DLT_RAW, rx_ph, NULL, 0);

		rx_ring_stats.kcrsi_slots_transferred++;
		rx_ring_stats.kcrsi_bytes_transferred += length;

		if (!pcb->ipsec_ext_ifdata_stats) {
			ifnet_stat_increment_in(pcb->ipsec_ifp, 1, length, 0);
		}

		mbuf_freem(data);

		// Advance ring
		rx_pslot = rx_slot;
		rx_slot = kern_channel_get_next_slot(rx_ring, rx_slot, NULL);
	}

	for (uint8_t ring_idx = 0; ring_idx < pcb->ipsec_kpipe_count; ring_idx++) {
		struct kern_channel_ring_stat_increment tx_ring_stats;
		bzero(&tx_ring_stats, sizeof(tx_ring_stats));
		kern_channel_ring_t tx_ring = pcb->ipsec_kpipe_txring[ring_idx];
		kern_channel_slot_t tx_pslot = NULL;
		kern_channel_slot_t tx_slot = NULL;
		if (tx_ring == NULL) {
			// Net-If TX ring not set up yet, nothing to read
			goto done;
		}


		// Unlock ipsec before entering ring
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);

		(void)kr_enter(tx_ring, TRUE);

		// Lock again after entering and validate
		lck_rw_lock_shared(&pcb->ipsec_pcb_lock);

		if (tx_ring != pcb->ipsec_kpipe_txring[ring_idx]) {
			goto done;
		}

		tx_slot = kern_channel_get_next_slot(tx_ring, NULL, NULL);
		if (tx_slot == NULL) {
			// Nothing to read, don't bother signalling
			goto done;
		}

		while (rx_slot != NULL && tx_slot != NULL) {
			size_t length = 0;
			mbuf_t data = NULL;
			errno_t error = 0;
			uint32_t af;

			// Allocate rx packet
			kern_packet_t rx_ph = 0;
			error = kern_pbufpool_alloc_nosleep(rx_pp, 1, &rx_ph);
			if (__improbable(error != 0)) {
				STATS_INC(nifs, NETIF_STATS_DROP_NOMEM_PKT);
				STATS_INC(nifs, NETIF_STATS_DROP);
				break;
			}

			kern_packet_t tx_ph = kern_channel_slot_get_packet(tx_ring, tx_slot);

			// Advance TX ring
			tx_pslot = tx_slot;
			tx_slot = kern_channel_get_next_slot(tx_ring, tx_slot, NULL);

			if (tx_ph == 0) {
				kern_pbufpool_free(rx_pp, rx_ph);
				continue;
			}

			kern_buflet_t tx_buf = kern_packet_get_next_buflet(tx_ph, NULL);
			VERIFY(tx_buf != NULL);
			uint8_t *tx_baddr = kern_buflet_get_object_address(tx_buf);
			VERIFY(tx_baddr != 0);
			tx_baddr += kern_buflet_get_data_offset(tx_buf);

			length = MIN(kern_packet_get_data_length(tx_ph),
			    pcb->ipsec_slot_size);

			// Increment TX stats
			tx_ring_stats.kcrsi_slots_transferred++;
			tx_ring_stats.kcrsi_bytes_transferred += length;

			if (length >= sizeof(struct ip)) {
				error = mbuf_gethdr(MBUF_DONTWAIT, MBUF_TYPE_HEADER, &data);
				if (error == 0) {
					error = mbuf_copyback(data, 0, length, tx_baddr, MBUF_DONTWAIT);
					if (error == 0) {
						lck_mtx_lock(&pcb->ipsec_kpipe_decrypt_lock);
						struct ip *ip = mtod(data, struct ip *);
						u_int ip_version = ip->ip_v;
						switch (ip_version) {
						case 4: {
							af = AF_INET;
							ip->ip_len = ntohs(ip->ip_len) - sizeof(struct ip);
							ip->ip_off = ntohs(ip->ip_off);

							if (length < ip->ip_len) {
								os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: IPv4 packet length too short (%zu < %u)\n",
								    pcb->ipsec_ifp->if_xname, length, ip->ip_len);
								STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
								STATS_INC(nifs, NETIF_STATS_DROP);
								mbuf_freem(data);
								data = NULL;
							} else {
								data = esp4_input_extended(data, sizeof(struct ip), pcb->ipsec_ifp);
							}
							break;
						}
						case 6: {
							if (length < sizeof(struct ip6_hdr)) {
								os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: IPv6 packet length too short for header %zu\n",
								    pcb->ipsec_ifp->if_xname, length);
								STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
								STATS_INC(nifs, NETIF_STATS_DROP);
								mbuf_freem(data);
								data = NULL;
							} else {
								af = AF_INET6;
								struct ip6_hdr *ip6 = mtod(data, struct ip6_hdr *);
								const size_t ip6_len = sizeof(*ip6) + ntohs(ip6->ip6_plen);
								if (length < ip6_len) {
									os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: IPv6 packet length too short (%zu < %zu)\n",
									    pcb->ipsec_ifp->if_xname, length, ip6_len);
									STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
									STATS_INC(nifs, NETIF_STATS_DROP);
									mbuf_freem(data);
									data = NULL;
								} else {
									int offset = sizeof(struct ip6_hdr);
									esp6_input_extended(&data, &offset, ip6->ip6_nxt, pcb->ipsec_ifp);
								}
							}
							break;
						}
						default: {
							os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: unknown ip version %u\n",
							    pcb->ipsec_ifp->if_xname, ip_version);
							STATS_INC(nifs, NETIF_STATS_DROP);
							mbuf_freem(data);
							data = NULL;
							break;
						}
						}
						lck_mtx_unlock(&pcb->ipsec_kpipe_decrypt_lock);
					} else {
						os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s - mbuf_copyback(%zu) error %d\n", pcb->ipsec_ifp->if_xname, length, error);
						STATS_INC(nifs, NETIF_STATS_DROP_NOMEM_MBUF);
						STATS_INC(nifs, NETIF_STATS_DROP);
						mbuf_freem(data);
						data = NULL;
					}
				} else {
					os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s - mbuf_gethdr error %d\n", pcb->ipsec_ifp->if_xname, error);
					STATS_INC(nifs, NETIF_STATS_DROP_NOMEM_MBUF);
					STATS_INC(nifs, NETIF_STATS_DROP);
				}
			} else {
				os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s - bad packet length %zu\n", pcb->ipsec_ifp->if_xname, length);
				STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
				STATS_INC(nifs, NETIF_STATS_DROP);
			}

			if (data == NULL) {
				// Failed to get decrypted data data
				kern_pbufpool_free(rx_pp, rx_ph);
				continue;
			}

			length = mbuf_pkthdr_len(data);
			if (length > rx_pp->pp_buflet_size) {
				// Flush data
				mbuf_freem(data);
				kern_pbufpool_free(rx_pp, rx_ph);
				STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
				STATS_INC(nifs, NETIF_STATS_DROP);
				os_log_error(OS_LOG_DEFAULT, "ipsec_netif_sync_rx %s: decrypted packet length %zu > %u\n",
				    pcb->ipsec_ifp->if_xname, length, rx_pp->pp_buflet_size);
				continue;
			}

			mbuf_pkthdr_setrcvif(data, pcb->ipsec_ifp);

			// Fillout rx packet
			kern_buflet_t rx_buf = kern_packet_get_next_buflet(rx_ph, NULL);
			VERIFY(rx_buf != NULL);
			void *rx_baddr = kern_buflet_get_object_address(rx_buf);
			VERIFY(rx_baddr != NULL);

			// Copy-in data from mbuf to buflet
			mbuf_copydata(data, 0, length, (void *)rx_baddr);
			kern_packet_clear_flow_uuid(rx_ph);     // Zero flow id

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

			STATS_INC(nifs, NETIF_STATS_RX_PACKETS);
			STATS_INC(nifs, NETIF_STATS_RX_COPY_DIRECT);
			bpf_tap_packet_in(pcb->ipsec_ifp, DLT_RAW, rx_ph, NULL, 0);

			rx_ring_stats.kcrsi_slots_transferred++;
			rx_ring_stats.kcrsi_bytes_transferred += length;

			if (!pcb->ipsec_ext_ifdata_stats) {
				ifnet_stat_increment_in(pcb->ipsec_ifp, 1, length, 0);
			}

			mbuf_freem(data);

			rx_pslot = rx_slot;
			rx_slot = kern_channel_get_next_slot(rx_ring, rx_slot, NULL);
		}

done:
		if (tx_pslot) {
			kern_channel_advance_slot(tx_ring, tx_pslot);
			kern_channel_increment_ring_net_stats(tx_ring, pcb->ipsec_ifp, &tx_ring_stats);
			(void)kern_channel_reclaim(tx_ring);
		}

		// Unlock first, then exit ring
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		if (tx_ring != NULL) {
			if (tx_pslot != NULL) {
				kern_channel_notify(tx_ring, 0);
			}
			kr_exit(tx_ring);
		}

		lck_rw_lock_shared(&pcb->ipsec_pcb_lock);
	}

	if (rx_pslot) {
		kern_channel_advance_slot(rx_ring, rx_pslot);
		kern_channel_increment_ring_net_stats(rx_ring, pcb->ipsec_ifp, &rx_ring_stats);
	}


	lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);

	ipsec_data_move_end(pcb);
	return 0;
}

static errno_t
ipsec_nexus_ifattach(struct ipsec_pcb *pcb,
    struct ifnet_init_eparams *init_params,
    struct ifnet **ifp)
{
	errno_t err;
	nexus_controller_t controller = kern_nexus_shared_controller();
	struct kern_nexus_net_init net_init;
	struct kern_pbufpool_init pp_init;

	nexus_name_t provider_name;
	snprintf((char *)provider_name, sizeof(provider_name),
	    "com.apple.netif.%s", pcb->ipsec_if_xname);

	struct kern_nexus_provider_init prov_init = {
		.nxpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxpi_flags = NXPIF_VIRTUAL_DEVICE,
		.nxpi_pre_connect = ipsec_nexus_pre_connect,
		.nxpi_connected = ipsec_nexus_connected,
		.nxpi_pre_disconnect = ipsec_netif_pre_disconnect,
		.nxpi_disconnected = ipsec_nexus_disconnected,
		.nxpi_ring_init = ipsec_netif_ring_init,
		.nxpi_ring_fini = ipsec_netif_ring_fini,
		.nxpi_slot_init = NULL,
		.nxpi_slot_fini = NULL,
		.nxpi_sync_tx = ipsec_netif_sync_tx,
		.nxpi_sync_rx = ipsec_netif_sync_rx,
		.nxpi_tx_doorbell = ipsec_netif_tx_doorbell,
	};

	nexus_attr_t nxa = NULL;
	err = kern_nexus_attr_create(&nxa);
	IPSEC_IF_VERIFY(err == 0);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s: kern_nexus_attr_create failed: %d\n",
		    __func__, err);
		goto failed;
	}

	uint64_t slot_buffer_size = pcb->ipsec_slot_size;
	err = kern_nexus_attr_set(nxa, NEXUS_ATTR_SLOT_BUF_SIZE, slot_buffer_size);
	VERIFY(err == 0);

	// Reset ring size for netif nexus to limit memory usage
	uint64_t ring_size = pcb->ipsec_netif_ring_size;
	err = kern_nexus_attr_set(nxa, NEXUS_ATTR_TX_SLOTS, ring_size);
	VERIFY(err == 0);
	err = kern_nexus_attr_set(nxa, NEXUS_ATTR_RX_SLOTS, ring_size);
	VERIFY(err == 0);

	assert(err == 0);

	if (ipsec_in_wmm_mode(pcb)) {
		os_log(OS_LOG_DEFAULT, "%s: %s enabling wmm mode\n",
		    __func__, pcb->ipsec_if_xname);

		init_params->output_sched_model = IFNET_SCHED_MODEL_DRIVER_MANAGED;

		err = kern_nexus_attr_set(nxa, NEXUS_ATTR_TX_RINGS,
		    IPSEC_NETIF_WMM_TX_RING_COUNT);
		VERIFY(err == 0);
		err = kern_nexus_attr_set(nxa, NEXUS_ATTR_RX_RINGS,
		    IPSEC_NETIF_WMM_RX_RING_COUNT);
		VERIFY(err == 0);

		err = kern_nexus_attr_set(nxa, NEXUS_ATTR_QMAP, NEXUS_QMAP_TYPE_WMM);
		VERIFY(err == 0);
	}

	pcb->ipsec_netif_txring_size = ring_size;

	bzero(&pp_init, sizeof(pp_init));
	pp_init.kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init.kbi_flags |= KBIF_VIRTUAL_DEVICE;
	// Note: we need more packets than can be held in the tx and rx rings because
	// packets can also be in the AQM queue(s)
	pp_init.kbi_packets = pcb->ipsec_netif_ring_size * (2 * pcb->ipsec_kpipe_count + 1);
	pp_init.kbi_bufsize = pcb->ipsec_slot_size;
	pp_init.kbi_buf_seg_size = IPSEC_IF_DEFAULT_BUF_SEG_SIZE;
	pp_init.kbi_max_frags = 1;
	(void) snprintf((char *)pp_init.kbi_name, sizeof(pp_init.kbi_name),
	    "%s", provider_name);
	pp_init.kbi_ctx = NULL;
	pp_init.kbi_ctx_retain = NULL;
	pp_init.kbi_ctx_release = NULL;

	err = kern_pbufpool_create(&pp_init, &pcb->ipsec_netif_pp, NULL);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s pbufbool create failed, error %d\n", __func__, err);
		goto failed;
	}

	err = kern_nexus_controller_register_provider(controller,
	    ipsec_nx_dom_prov,
	    provider_name,
	    &prov_init,
	    sizeof(prov_init),
	    nxa,
	    &pcb->ipsec_nx.if_provider);
	IPSEC_IF_VERIFY(err == 0);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s register provider failed, error %d\n",
		    __func__, err);
		goto failed;
	}

	bzero(&net_init, sizeof(net_init));
	net_init.nxneti_version = KERN_NEXUS_NET_CURRENT_VERSION;
	net_init.nxneti_flags = 0;
	net_init.nxneti_eparams = init_params;
	net_init.nxneti_lladdr = NULL;
	net_init.nxneti_prepare = ipsec_netif_prepare;
	net_init.nxneti_tx_pbufpool = pcb->ipsec_netif_pp;
	err = kern_nexus_controller_alloc_net_provider_instance(controller,
	    pcb->ipsec_nx.if_provider,
	    pcb,
	    &pcb->ipsec_nx.if_instance,
	    &net_init,
	    ifp);
	IPSEC_IF_VERIFY(err == 0);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s alloc_net_provider_instance failed, %d\n",
		    __func__, err);
		kern_nexus_controller_deregister_provider(controller,
		    pcb->ipsec_nx.if_provider);
		uuid_clear(pcb->ipsec_nx.if_provider);
		goto failed;
	}

failed:
	if (nxa) {
		kern_nexus_attr_destroy(nxa);
	}
	if (err && pcb->ipsec_netif_pp != NULL) {
		kern_pbufpool_destroy(pcb->ipsec_netif_pp);
		pcb->ipsec_netif_pp = NULL;
	}
	return err;
}

static void
ipsec_detach_provider_and_instance(uuid_t provider, uuid_t instance)
{
	nexus_controller_t controller = kern_nexus_shared_controller();
	errno_t err;

	if (!uuid_is_null(instance)) {
		err = kern_nexus_controller_free_provider_instance(controller,
		    instance);
		if (err != 0) {
			os_log_error(OS_LOG_DEFAULT, "%s free_provider_instance failed %d\n",
			    __func__, err);
		}
		uuid_clear(instance);
	}
	if (!uuid_is_null(provider)) {
		err = kern_nexus_controller_deregister_provider(controller,
		    provider);
		if (err != 0) {
			os_log_error(OS_LOG_DEFAULT, "%s deregister_provider %d\n", __func__, err);
		}
		uuid_clear(provider);
	}
	return;
}

static void
ipsec_nexus_detach(struct ipsec_pcb *pcb)
{
	ipsec_nx_t nx = &pcb->ipsec_nx;
	nexus_controller_t controller = kern_nexus_shared_controller();
	errno_t err;

	if (!uuid_is_null(nx->fsw_host)) {
		err = kern_nexus_ifdetach(controller,
		    nx->fsw_instance,
		    nx->fsw_host);
		if (err != 0) {
			os_log_error(OS_LOG_DEFAULT, "%s: kern_nexus_ifdetach ms host failed %d\n",
			    __func__, err);
		}
	}

	if (!uuid_is_null(nx->fsw_device)) {
		err = kern_nexus_ifdetach(controller,
		    nx->fsw_instance,
		    nx->fsw_device);
		if (err != 0) {
			os_log_error(OS_LOG_DEFAULT, "%s: kern_nexus_ifdetach ms device failed %d\n",
			    __func__, err);
		}
	}

	ipsec_detach_provider_and_instance(nx->if_provider,
	    nx->if_instance);
	ipsec_detach_provider_and_instance(nx->fsw_provider,
	    nx->fsw_instance);

	if (pcb->ipsec_netif_pp != NULL) {
		kern_pbufpool_destroy(pcb->ipsec_netif_pp);
		pcb->ipsec_netif_pp = NULL;
	}
	memset(nx, 0, sizeof(*nx));
}

static errno_t
ipsec_create_fs_provider_and_instance(struct ipsec_pcb *pcb,
    const char *type_name,
    const char *ifname,
    uuid_t *provider, uuid_t *instance)
{
	nexus_attr_t attr = NULL;
	nexus_controller_t controller = kern_nexus_shared_controller();
	uuid_t dom_prov;
	errno_t err;
	struct kern_nexus_init init;
	nexus_name_t    provider_name;

	err = kern_nexus_get_default_domain_provider(NEXUS_TYPE_FLOW_SWITCH,
	    &dom_prov);
	IPSEC_IF_VERIFY(err == 0);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s can't get %s provider, error %d\n",
		    __func__, type_name, err);
		goto failed;
	}

	err = kern_nexus_attr_create(&attr);
	IPSEC_IF_VERIFY(err == 0);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s: kern_nexus_attr_create failed: %d\n",
		    __func__, err);
		goto failed;
	}

	uint64_t slot_buffer_size = pcb->ipsec_slot_size;
	err = kern_nexus_attr_set(attr, NEXUS_ATTR_SLOT_BUF_SIZE, slot_buffer_size);
	VERIFY(err == 0);

	// Reset ring size for flowswitch nexus to limit memory usage. Larger RX than netif.
	uint64_t tx_ring_size = pcb->ipsec_tx_fsw_ring_size;
	err = kern_nexus_attr_set(attr, NEXUS_ATTR_TX_SLOTS, tx_ring_size);
	VERIFY(err == 0);
	uint64_t rx_ring_size = pcb->ipsec_rx_fsw_ring_size;
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
	IPSEC_IF_VERIFY(err == 0);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s register %s provider failed, error %d\n",
		    __func__, type_name, err);
		goto failed;
	}
	bzero(&init, sizeof(init));
	init.nxi_version = KERN_NEXUS_CURRENT_VERSION;
	err = kern_nexus_controller_alloc_provider_instance(controller,
	    *provider,
	    NULL,
	    instance, &init);
	IPSEC_IF_VERIFY(err == 0);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s alloc_provider_instance %s failed, %d\n",
		    __func__, type_name, err);
		kern_nexus_controller_deregister_provider(controller,
		    *provider);
		uuid_clear(*provider);
	}
failed:
	return err;
}

static errno_t
ipsec_flowswitch_attach(struct ipsec_pcb *pcb)
{
	nexus_controller_t controller = kern_nexus_shared_controller();
	errno_t err = 0;
	ipsec_nx_t nx = &pcb->ipsec_nx;

	// Allocate flowswitch
	err = ipsec_create_fs_provider_and_instance(pcb,
	    "flowswitch",
	    pcb->ipsec_ifp->if_xname,
	    &nx->fsw_provider,
	    &nx->fsw_instance);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s: failed to create bridge provider and instance\n",
		    __func__);
		goto failed;
	}

	// Attach flowswitch to device port
	err = kern_nexus_ifattach(controller, nx->fsw_instance,
	    NULL, nx->if_instance,
	    FALSE, &nx->fsw_device);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s kern_nexus_ifattach ms device %d\n", __func__, err);
		goto failed;
	}

	// Attach flowswitch to host port
	err = kern_nexus_ifattach(controller, nx->fsw_instance,
	    NULL, nx->if_instance,
	    TRUE, &nx->fsw_host);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s kern_nexus_ifattach ms host %d\n", __func__, err);
		goto failed;
	}

	// Extract the agent UUID and save for later
	struct kern_nexus *flowswitch_nx = nx_find(nx->fsw_instance, false);
	if (flowswitch_nx != NULL) {
		struct nx_flowswitch *flowswitch = NX_FSW_PRIVATE(flowswitch_nx);
		if (flowswitch != NULL) {
			FSW_RLOCK(flowswitch);
			uuid_copy(nx->fsw_agent, flowswitch->fsw_agent_uuid);
			FSW_UNLOCK(flowswitch);
		} else {
			os_log_error(OS_LOG_DEFAULT, "ipsec_flowswitch_attach - flowswitch is NULL\n");
		}
		nx_release(flowswitch_nx);
	} else {
		os_log_error(OS_LOG_DEFAULT, "ipsec_flowswitch_attach - unable to find flowswitch nexus\n");
	}

	return 0;

failed:
	ipsec_nexus_detach(pcb);

	errno_t detach_error = 0;
	if ((detach_error = ifnet_detach(pcb->ipsec_ifp)) != 0) {
		panic("ipsec_flowswitch_attach - ifnet_detach failed: %d\n", detach_error);
		/* NOT REACHED */
	}

	return err;
}

#pragma mark Kernel Pipe Nexus

static errno_t
ipsec_register_kernel_pipe_nexus(struct ipsec_pcb *pcb)
{
	nexus_attr_t nxa = NULL;
	errno_t result;

	lck_mtx_lock(&ipsec_lock);
	if (ipsec_ncd_refcount++) {
		lck_mtx_unlock(&ipsec_lock);
		return 0;
	}

	result = kern_nexus_controller_create(&ipsec_ncd);
	if (result) {
		os_log_error(OS_LOG_DEFAULT, "%s: kern_nexus_controller_create failed: %d\n",
		    __FUNCTION__, result);
		goto done;
	}

	uuid_t dom_prov;
	result = kern_nexus_get_default_domain_provider(
		NEXUS_TYPE_KERNEL_PIPE, &dom_prov);
	if (result) {
		os_log_error(OS_LOG_DEFAULT, "%s: kern_nexus_get_default_domain_provider failed: %d\n",
		    __FUNCTION__, result);
		goto done;
	}

	struct kern_nexus_provider_init prov_init = {
		.nxpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxpi_flags = NXPIF_VIRTUAL_DEVICE,
		.nxpi_pre_connect = ipsec_nexus_pre_connect,
		.nxpi_connected = ipsec_nexus_connected,
		.nxpi_pre_disconnect = ipsec_nexus_pre_disconnect,
		.nxpi_disconnected = ipsec_nexus_disconnected,
		.nxpi_ring_init = ipsec_kpipe_ring_init,
		.nxpi_ring_fini = ipsec_kpipe_ring_fini,
		.nxpi_slot_init = NULL,
		.nxpi_slot_fini = NULL,
		.nxpi_sync_tx = ipsec_kpipe_sync_tx,
		.nxpi_sync_rx = ipsec_kpipe_sync_rx,
		.nxpi_tx_doorbell = NULL,
	};

	result = kern_nexus_attr_create(&nxa);
	if (result) {
		os_log_error(OS_LOG_DEFAULT, "%s: kern_nexus_attr_create failed: %d\n",
		    __FUNCTION__, result);
		goto done;
	}

	uint64_t slot_buffer_size = IPSEC_IF_DEFAULT_SLOT_SIZE;
	result = kern_nexus_attr_set(nxa, NEXUS_ATTR_SLOT_BUF_SIZE, slot_buffer_size);
	VERIFY(result == 0);

	// Reset ring size for kernel pipe nexus to limit memory usage
	// Note: It's better to have less on slots on the kpipe TX ring than the netif
	// so back pressure is applied at the AQM layer
	uint64_t ring_size =
	    pcb->ipsec_kpipe_tx_ring_size != 0 ? pcb->ipsec_kpipe_tx_ring_size :
	    pcb->ipsec_netif_ring_size != 0 ? pcb->ipsec_netif_ring_size :
	    if_ipsec_ring_size;
	result = kern_nexus_attr_set(nxa, NEXUS_ATTR_TX_SLOTS, ring_size);
	VERIFY(result == 0);

	ring_size =
	    pcb->ipsec_kpipe_rx_ring_size != 0 ? pcb->ipsec_kpipe_rx_ring_size :
	    pcb->ipsec_netif_ring_size != 0 ? pcb->ipsec_netif_ring_size :
	    if_ipsec_ring_size;
	result = kern_nexus_attr_set(nxa, NEXUS_ATTR_RX_SLOTS, ring_size);
	VERIFY(result == 0);

	result = kern_nexus_controller_register_provider(ipsec_ncd,
	    dom_prov,
	    (const uint8_t *)"com.apple.nexus.ipsec.kpipe",
	    &prov_init,
	    sizeof(prov_init),
	    nxa,
	    &ipsec_kpipe_uuid);
	if (result) {
		os_log_error(OS_LOG_DEFAULT, "%s: kern_nexus_controller_register_provider failed: %d\n",
		    __FUNCTION__, result);
		goto done;
	}

done:
	if (nxa) {
		kern_nexus_attr_destroy(nxa);
	}

	if (result) {
		if (ipsec_ncd) {
			kern_nexus_controller_destroy(ipsec_ncd);
			ipsec_ncd = NULL;
		}
		ipsec_ncd_refcount = 0;
	}

	lck_mtx_unlock(&ipsec_lock);

	return result;
}

static void
ipsec_unregister_kernel_pipe_nexus(void)
{
	lck_mtx_lock(&ipsec_lock);

	VERIFY(ipsec_ncd_refcount > 0);

	if (--ipsec_ncd_refcount == 0) {
		kern_nexus_controller_destroy(ipsec_ncd);
		ipsec_ncd = NULL;
	}

	lck_mtx_unlock(&ipsec_lock);
}

/* This structure only holds onto kpipe channels that need to be
 * freed in the future, but are cleared from the pcb under lock
 */
struct ipsec_detached_channels {
	int count;
	kern_pbufpool_t pp;
	uuid_t uuids[IPSEC_IF_MAX_RING_COUNT];
};

static void
ipsec_detach_channels(struct ipsec_pcb *pcb, struct ipsec_detached_channels *dc)
{
	LCK_RW_ASSERT(&pcb->ipsec_pcb_lock, LCK_RW_TYPE_EXCLUSIVE);

	if (!ipsec_flag_isset(pcb, IPSEC_FLAGS_KPIPE_ALLOCATED)) {
		for (int i = 0; i < IPSEC_IF_MAX_RING_COUNT; i++) {
			VERIFY(uuid_is_null(pcb->ipsec_kpipe_uuid[i]));
		}
		dc->count = 0;
		return;
	}

	dc->count = pcb->ipsec_kpipe_count;

	VERIFY(dc->count >= 0);
	VERIFY(dc->count <= IPSEC_IF_MAX_RING_COUNT);

	for (int i = 0; i < dc->count; i++) {
		VERIFY(!uuid_is_null(pcb->ipsec_kpipe_uuid[i]));
		uuid_copy(dc->uuids[i], pcb->ipsec_kpipe_uuid[i]);
		uuid_clear(pcb->ipsec_kpipe_uuid[i]);
	}
	for (int i = dc->count; i < IPSEC_IF_MAX_RING_COUNT; i++) {
		VERIFY(uuid_is_null(pcb->ipsec_kpipe_uuid[i]));
	}

	if (dc->count) {
		VERIFY(pcb->ipsec_kpipe_pp);
	} else {
		VERIFY(!pcb->ipsec_kpipe_pp);
	}

	dc->pp = pcb->ipsec_kpipe_pp;

	pcb->ipsec_kpipe_pp = NULL;

	ipsec_flag_clr(pcb, IPSEC_FLAGS_KPIPE_ALLOCATED);
}

static void
ipsec_free_channels(struct ipsec_detached_channels *dc)
{
	if (!dc->count) {
		return;
	}

	for (int i = 0; i < dc->count; i++) {
		errno_t result;
		result = kern_nexus_controller_free_provider_instance(ipsec_ncd, dc->uuids[i]);
		VERIFY(!result);
	}

	VERIFY(dc->pp);
	kern_pbufpool_destroy(dc->pp);

	ipsec_unregister_kernel_pipe_nexus();

	memset(dc, 0, sizeof(*dc));
}

static errno_t
ipsec_enable_channel(struct ipsec_pcb *pcb, struct proc *proc)
{
	struct kern_nexus_init init;
	struct kern_pbufpool_init pp_init;
	errno_t result;

	kauth_cred_t cred = kauth_cred_get();
	result = priv_check_cred(cred, PRIV_SKYWALK_REGISTER_KERNEL_PIPE, 0);
	if (result) {
		return result;
	}

	VERIFY(pcb->ipsec_kpipe_count);
	VERIFY(!ipsec_flag_isset(pcb, IPSEC_FLAGS_KPIPE_ALLOCATED));

	result = ipsec_register_kernel_pipe_nexus(pcb);

	lck_rw_lock_exclusive(&pcb->ipsec_pcb_lock);

	if (result) {
		os_log_error(OS_LOG_DEFAULT, "%s: %s failed to register kernel pipe nexus\n",
		    __func__, pcb->ipsec_if_xname);
		goto done;
	}

	VERIFY(ipsec_ncd);

	bzero(&pp_init, sizeof(pp_init));
	pp_init.kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init.kbi_flags |= KBIF_VIRTUAL_DEVICE;
	// Note: We only needs are many packets as can be held in the tx and rx rings
	pp_init.kbi_packets = pcb->ipsec_netif_ring_size * 2 * pcb->ipsec_kpipe_count;
	pp_init.kbi_bufsize = pcb->ipsec_slot_size;
	pp_init.kbi_buf_seg_size = IPSEC_IF_DEFAULT_BUF_SEG_SIZE;
	pp_init.kbi_max_frags = 1;
	pp_init.kbi_flags |= KBIF_QUANTUM;
	(void) snprintf((char *)pp_init.kbi_name, sizeof(pp_init.kbi_name),
	    "com.apple.kpipe.%s", pcb->ipsec_if_xname);
	pp_init.kbi_ctx = NULL;
	pp_init.kbi_ctx_retain = NULL;
	pp_init.kbi_ctx_release = NULL;

	result = kern_pbufpool_create(&pp_init, &pcb->ipsec_kpipe_pp,
	    NULL);
	if (result != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s: %s pbufbool create failed, error %d\n",
		    __func__, pcb->ipsec_if_xname, result);
		goto done;
	}

	bzero(&init, sizeof(init));
	init.nxi_version = KERN_NEXUS_CURRENT_VERSION;
	init.nxi_tx_pbufpool = pcb->ipsec_kpipe_pp;

	for (unsigned int i = 0; i < pcb->ipsec_kpipe_count; i++) {
		VERIFY(uuid_is_null(pcb->ipsec_kpipe_uuid[i]));
		result = kern_nexus_controller_alloc_provider_instance(ipsec_ncd,
		    ipsec_kpipe_uuid, pcb, &pcb->ipsec_kpipe_uuid[i], &init);

		if (result == 0) {
			nexus_port_t port = NEXUS_PORT_KERNEL_PIPE_CLIENT;
			pid_t pid = pcb->ipsec_kpipe_pid;
			if (!pid) {
				pid = proc_pid(proc);
			}
			result = kern_nexus_controller_bind_provider_instance(ipsec_ncd,
			    pcb->ipsec_kpipe_uuid[i], &port,
			    pid, NULL, NULL, 0, NEXUS_BIND_PID);
		}

		if (result) {
			/* Unwind all of them on error */
			for (int j = 0; j < IPSEC_IF_MAX_RING_COUNT; j++) {
				if (!uuid_is_null(pcb->ipsec_kpipe_uuid[j])) {
					kern_nexus_controller_free_provider_instance(ipsec_ncd,
					    pcb->ipsec_kpipe_uuid[j]);
					uuid_clear(pcb->ipsec_kpipe_uuid[j]);
				}
			}
			goto done;
		}
	}

done:
	lck_rw_unlock_exclusive(&pcb->ipsec_pcb_lock);

	if (result) {
		if (pcb->ipsec_kpipe_pp != NULL) {
			kern_pbufpool_destroy(pcb->ipsec_kpipe_pp);
			pcb->ipsec_kpipe_pp = NULL;
		}
		ipsec_unregister_kernel_pipe_nexus();
	} else {
		ipsec_flag_set(pcb, IPSEC_FLAGS_KPIPE_ALLOCATED);
	}

	return result;
}

#endif // IPSEC_NEXUS


/* Kernel control functions */

static inline void
ipsec_free_pcb(struct ipsec_pcb *pcb, bool in_list)
{
#if IPSEC_NEXUS
	mbuf_freem_list(pcb->ipsec_input_chain);
	pcb->ipsec_input_chain_count = 0;
	lck_mtx_destroy(&pcb->ipsec_input_chain_lock, ipsec_lck_grp);
	lck_mtx_destroy(&pcb->ipsec_kpipe_encrypt_lock, ipsec_lck_grp);
	lck_mtx_destroy(&pcb->ipsec_kpipe_decrypt_lock, ipsec_lck_grp);
#endif // IPSEC_NEXUS
	lck_mtx_destroy(&pcb->ipsec_pcb_data_move_lock, ipsec_lck_grp);
	lck_rw_destroy(&pcb->ipsec_pcb_lock, ipsec_lck_grp);
	if (in_list) {
		lck_mtx_lock(&ipsec_lock);
		TAILQ_REMOVE(&ipsec_head, pcb, ipsec_chain);
		lck_mtx_unlock(&ipsec_lock);
	}
	zfree(ipsec_pcb_zone, pcb);
}

static errno_t
ipsec_ctl_bind(kern_ctl_ref kctlref,
    struct sockaddr_ctl *sac,
    void **unitinfo)
{
	struct ipsec_pcb *pcb = zalloc(ipsec_pcb_zone);
	memset(pcb, 0, sizeof(*pcb));

	/* Setup the protocol control block */
	*unitinfo = pcb;
	pcb->ipsec_ctlref = kctlref;
	pcb->ipsec_unit = sac->sc_unit;
	pcb->ipsec_output_service_class = MBUF_SC_OAM;

#if IPSEC_NEXUS
	pcb->ipsec_use_netif = false;
	pcb->ipsec_slot_size = IPSEC_IF_DEFAULT_SLOT_SIZE;
	pcb->ipsec_netif_ring_size = if_ipsec_ring_size;
	pcb->ipsec_tx_fsw_ring_size = if_ipsec_tx_fsw_ring_size;
	pcb->ipsec_rx_fsw_ring_size = if_ipsec_rx_fsw_ring_size;
#endif // IPSEC_NEXUS

	lck_rw_init(&pcb->ipsec_pcb_lock, ipsec_lck_grp, ipsec_lck_attr);
	lck_mtx_init(&pcb->ipsec_pcb_data_move_lock, ipsec_lck_grp, ipsec_lck_attr);
#if IPSEC_NEXUS
	pcb->ipsec_input_chain_count = 0;
	lck_mtx_init(&pcb->ipsec_input_chain_lock, ipsec_lck_grp, ipsec_lck_attr);
	lck_mtx_init(&pcb->ipsec_kpipe_encrypt_lock, ipsec_lck_grp, ipsec_lck_attr);
	lck_mtx_init(&pcb->ipsec_kpipe_decrypt_lock, ipsec_lck_grp, ipsec_lck_attr);
#endif // IPSEC_NEXUS

	return 0;
}

static errno_t
ipsec_ctl_connect(kern_ctl_ref kctlref,
    struct sockaddr_ctl *sac,
    void **unitinfo)
{
	struct ifnet_init_eparams ipsec_init = {};
	errno_t result = 0;

	if (*unitinfo == NULL) {
		(void)ipsec_ctl_bind(kctlref, sac, unitinfo);
	}

	struct ipsec_pcb *pcb = *unitinfo;
	if (pcb == NULL) {
		return EINVAL;
	}

	lck_mtx_lock(&ipsec_lock);

	/* Find some open interface id */
	u_int32_t chosen_unique_id = 1;
	struct ipsec_pcb *next_pcb = TAILQ_LAST(&ipsec_head, ipsec_list);
	if (next_pcb != NULL) {
		/* List was not empty, add one to the last item */
		chosen_unique_id = next_pcb->ipsec_unique_id + 1;
		next_pcb = NULL;

		/*
		 * If this wrapped the id number, start looking at
		 * the front of the list for an unused id.
		 */
		if (chosen_unique_id == 0) {
			/* Find the next unused ID */
			chosen_unique_id = 1;
			TAILQ_FOREACH(next_pcb, &ipsec_head, ipsec_chain) {
				if (next_pcb->ipsec_unique_id > chosen_unique_id) {
					/* We found a gap */
					break;
				}

				chosen_unique_id = next_pcb->ipsec_unique_id + 1;
			}
		}
	}

	pcb->ipsec_unique_id = chosen_unique_id;

	if (next_pcb != NULL) {
		TAILQ_INSERT_BEFORE(next_pcb, pcb, ipsec_chain);
	} else {
		TAILQ_INSERT_TAIL(&ipsec_head, pcb, ipsec_chain);
	}
	lck_mtx_unlock(&ipsec_lock);

	snprintf(pcb->ipsec_if_xname, sizeof(pcb->ipsec_if_xname), "ipsec%d", pcb->ipsec_unit - 1);
	snprintf(pcb->ipsec_unique_name, sizeof(pcb->ipsec_unique_name), "ipsecid%d", pcb->ipsec_unique_id - 1);
	os_log(OS_LOG_DEFAULT, "ipsec_ctl_connect: creating interface %s (id %s)\n", pcb->ipsec_if_xname, pcb->ipsec_unique_name);

	/* Create the interface */
	bzero(&ipsec_init, sizeof(ipsec_init));
	ipsec_init.ver = IFNET_INIT_CURRENT_VERSION;
	ipsec_init.len = sizeof(ipsec_init);

#if IPSEC_NEXUS
	if (pcb->ipsec_use_netif) {
		ipsec_init.flags = (IFNET_INIT_SKYWALK_NATIVE | IFNET_INIT_NX_NOAUTO);
	} else
#endif // IPSEC_NEXUS
	{
		ipsec_init.flags = IFNET_INIT_NX_NOAUTO;
		ipsec_init.start = ipsec_start;
	}
	ipsec_init.name = "ipsec";
	ipsec_init.unit = pcb->ipsec_unit - 1;
	ipsec_init.uniqueid = pcb->ipsec_unique_name;
	ipsec_init.uniqueid_len = strlen(pcb->ipsec_unique_name);
	ipsec_init.family = IFNET_FAMILY_IPSEC;
	ipsec_init.type = IFT_OTHER;
	ipsec_init.demux = ipsec_demux;
	ipsec_init.add_proto = ipsec_add_proto;
	ipsec_init.del_proto = ipsec_del_proto;
	ipsec_init.softc = pcb;
	ipsec_init.ioctl = ipsec_ioctl;
	ipsec_init.detach = ipsec_detached;

#if IPSEC_NEXUS
	/* We don't support kpipes without a netif */
	if (pcb->ipsec_kpipe_count && !pcb->ipsec_use_netif) {
		result = ENOTSUP;
		os_log_error(OS_LOG_DEFAULT, "ipsec_ctl_connect - kpipe requires netif: failed %d\n", result);
		ipsec_free_pcb(pcb, true);
		*unitinfo = NULL;
		return result;
	}

	if (if_ipsec_debug != 0) {
		printf("%s: %s%d use_netif %d kpipe_count %d slot_size %u ring_size %u "
		    "kpipe_tx_ring_size %u kpipe_rx_ring_size %u\n",
		    __func__,
		    ipsec_init.name, ipsec_init.unit,
		    pcb->ipsec_use_netif,
		    pcb->ipsec_kpipe_count,
		    pcb->ipsec_slot_size,
		    pcb->ipsec_netif_ring_size,
		    pcb->ipsec_kpipe_tx_ring_size,
		    pcb->ipsec_kpipe_rx_ring_size);
	}
	if (pcb->ipsec_use_netif) {
		if (pcb->ipsec_kpipe_count) {
			result = ipsec_enable_channel(pcb, current_proc());
			if (result) {
				os_log_error(OS_LOG_DEFAULT, "%s: %s failed to enable channels\n",
				    __func__, pcb->ipsec_if_xname);
				ipsec_free_pcb(pcb, true);
				*unitinfo = NULL;
				return result;
			}
		}

		result = ipsec_nexus_ifattach(pcb, &ipsec_init, &pcb->ipsec_ifp);
		if (result != 0) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_ctl_connect - ipsec_nexus_ifattach failed: %d\n", result);
			ipsec_free_pcb(pcb, true);
			*unitinfo = NULL;
			return result;
		}

		result = ipsec_flowswitch_attach(pcb);
		if (result != 0) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_ctl_connect - ipsec_flowswitch_attach failed: %d\n", result);
			// Do not call ipsec_free_pcb(). We will be attached already, and will be freed later
			// in ipsec_detached().
			*unitinfo = NULL;
			return result;
		}

		/* Attach to bpf */
		bpfattach(pcb->ipsec_ifp, DLT_RAW, 0);
	} else
#endif // IPSEC_NEXUS
	{
		result = ifnet_allocate_extended(&ipsec_init, &pcb->ipsec_ifp);
		if (result != 0) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_ctl_connect - ifnet_allocate failed: %d\n", result);
			ipsec_free_pcb(pcb, true);
			*unitinfo = NULL;
			return result;
		}
		ipsec_ifnet_set_attrs(pcb->ipsec_ifp);

		/* Attach the interface */
		result = ifnet_attach(pcb->ipsec_ifp, NULL);
		if (result != 0) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_ctl_connect - ifnet_attach failed: %d\n", result);
			ifnet_release(pcb->ipsec_ifp);
			ipsec_free_pcb(pcb, true);
			*unitinfo = NULL;
			return result;
		}

		/* Attach to bpf */
		bpfattach(pcb->ipsec_ifp, DLT_NULL, 0);
	}

#if IPSEC_NEXUS
	/*
	 * Mark the data path as ready.
	 * If kpipe nexus is being used then the data path is marked ready only when a kpipe channel is connected.
	 */
	if (pcb->ipsec_kpipe_count == 0) {
		lck_mtx_lock(&pcb->ipsec_pcb_data_move_lock);
		IPSEC_SET_DATA_PATH_READY(pcb);
		lck_mtx_unlock(&pcb->ipsec_pcb_data_move_lock);
	}
#endif

	/* The interfaces resoures allocated, mark it as running */
	ifnet_set_flags(pcb->ipsec_ifp, IFF_RUNNING, IFF_RUNNING);

	return 0;
}

static errno_t
ipsec_detach_ip(ifnet_t                         interface,
    protocol_family_t       protocol,
    socket_t                        pf_socket)
{
	errno_t result = EPROTONOSUPPORT;

	/* Attempt a detach */
	if (protocol == PF_INET) {
		struct ifreq    ifr;

		bzero(&ifr, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d",
		    ifnet_name(interface), ifnet_unit(interface));

		result = sock_ioctl(pf_socket, SIOCPROTODETACH, &ifr);
	} else if (protocol == PF_INET6) {
		struct in6_ifreq        ifr6;

		bzero(&ifr6, sizeof(ifr6));
		snprintf(ifr6.ifr_name, sizeof(ifr6.ifr_name), "%s%d",
		    ifnet_name(interface), ifnet_unit(interface));

		result = sock_ioctl(pf_socket, SIOCPROTODETACH_IN6, &ifr6);
	}

	return result;
}

static void
ipsec_remove_address(ifnet_t                            interface,
    protocol_family_t      protocol,
    ifaddr_t                       address,
    socket_t                       pf_socket)
{
	errno_t result = 0;

	/* Attempt a detach */
	if (protocol == PF_INET) {
		struct ifreq    ifr;

		bzero(&ifr, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d",
		    ifnet_name(interface), ifnet_unit(interface));
		result = ifaddr_address(address, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
		if (result != 0) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_remove_address - ifaddr_address failed: %d", result);
		} else {
			result = sock_ioctl(pf_socket, SIOCDIFADDR, &ifr);
			if (result != 0) {
				os_log_error(OS_LOG_DEFAULT, "ipsec_remove_address - SIOCDIFADDR failed: %d", result);
			}
		}
	} else if (protocol == PF_INET6) {
		struct in6_ifreq        ifr6;

		bzero(&ifr6, sizeof(ifr6));
		snprintf(ifr6.ifr_name, sizeof(ifr6.ifr_name), "%s%d",
		    ifnet_name(interface), ifnet_unit(interface));
		result = ifaddr_address(address, (struct sockaddr*)&ifr6.ifr_addr,
		    sizeof(ifr6.ifr_addr));
		if (result != 0) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_remove_address - ifaddr_address failed (v6): %d",
			    result);
		} else {
			result = sock_ioctl(pf_socket, SIOCDIFADDR_IN6, &ifr6);
			if (result != 0) {
				os_log_error(OS_LOG_DEFAULT, "ipsec_remove_address - SIOCDIFADDR_IN6 failed: %d",
				    result);
			}
		}
	}
}

static void
ipsec_cleanup_family(ifnet_t                            interface,
    protocol_family_t      protocol)
{
	errno_t         result = 0;
	socket_t        pf_socket = NULL;
	ifaddr_t        *addresses = NULL;
	int                     i;

	if (protocol != PF_INET && protocol != PF_INET6) {
		os_log_error(OS_LOG_DEFAULT, "ipsec_cleanup_family - invalid protocol family %d\n", protocol);
		return;
	}

	/* Create a socket for removing addresses and detaching the protocol */
	result = sock_socket(protocol, SOCK_DGRAM, 0, NULL, NULL, &pf_socket);
	if (result != 0) {
		if (result != EAFNOSUPPORT) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_cleanup_family - failed to create %s socket: %d\n",
			    protocol == PF_INET ? "IP" : "IPv6", result);
		}
		goto cleanup;
	}

	/* always set SS_PRIV, we want to close and detach regardless */
	sock_setpriv(pf_socket, 1);

	result = ipsec_detach_ip(interface, protocol, pf_socket);
	if (result == 0 || result == ENXIO) {
		/* We are done! We either detached or weren't attached. */
		goto cleanup;
	} else if (result != EBUSY) {
		/* Uh, not really sure what happened here... */
		os_log_error(OS_LOG_DEFAULT, "ipsec_cleanup_family - ipsec_detach_ip failed: %d\n", result);
		goto cleanup;
	}

	/*
	 * At this point, we received an EBUSY error. This means there are
	 * addresses attached. We should detach them and then try again.
	 */
	result = ifnet_get_address_list_family(interface, &addresses, protocol);
	if (result != 0) {
		os_log_error(OS_LOG_DEFAULT, "fnet_get_address_list_family(%s%d, 0xblah, %s) - failed: %d\n",
		    ifnet_name(interface), ifnet_unit(interface),
		    protocol == PF_INET ? "PF_INET" : "PF_INET6", result);
		goto cleanup;
	}

	for (i = 0; addresses[i] != 0; i++) {
		ipsec_remove_address(interface, protocol, addresses[i], pf_socket);
	}
	ifnet_free_address_list(addresses);
	addresses = NULL;

	/*
	 * The addresses should be gone, we should try the remove again.
	 */
	result = ipsec_detach_ip(interface, protocol, pf_socket);
	if (result != 0 && result != ENXIO) {
		os_log_error(OS_LOG_DEFAULT, "ipsec_cleanup_family - ipsec_detach_ip failed: %d\n", result);
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
ipsec_ctl_disconnect(__unused kern_ctl_ref      kctlref,
    __unused u_int32_t             unit,
    void                                   *unitinfo)
{
	struct ipsec_pcb *pcb = unitinfo;
	ifnet_t ifp = NULL;
	errno_t result = 0;

	if (pcb == NULL) {
		return EINVAL;
	}

	/* Wait until all threads in the data paths are done. */
	ipsec_wait_data_move_drain(pcb);

#if IPSEC_NEXUS
	// Tell the nexus to stop all rings
	if (pcb->ipsec_netif_nexus != NULL) {
		kern_nexus_stop(pcb->ipsec_netif_nexus);
	}
#endif // IPSEC_NEXUS

	lck_rw_lock_exclusive(&pcb->ipsec_pcb_lock);

#if IPSEC_NEXUS
	if (if_ipsec_debug != 0) {
		printf("ipsec_ctl_disconnect: detaching interface %s (id %s)\n",
		    pcb->ipsec_if_xname, pcb->ipsec_unique_name);
	}

	struct ipsec_detached_channels dc;
	ipsec_detach_channels(pcb, &dc);
#endif // IPSEC_NEXUS

	pcb->ipsec_ctlref = NULL;

	ifp = pcb->ipsec_ifp;
	if (ifp != NULL) {
#if IPSEC_NEXUS
		if (pcb->ipsec_netif_nexus != NULL) {
			/*
			 * Quiesce the interface and flush any pending outbound packets.
			 */
			if_down(ifp);

			/* Increment refcnt, but detach interface */
			ifnet_incr_iorefcnt(ifp);
			if ((result = ifnet_detach(ifp)) != 0) {
				panic("ipsec_ctl_disconnect - ifnet_detach failed: %d\n", result);
				/* NOT REACHED */
			}

			/*
			 * We want to do everything in our power to ensure that the interface
			 * really goes away when the socket is closed. We must remove IP/IPv6
			 * addresses and detach the protocols. Finally, we can remove and
			 * release the interface.
			 */
			key_delsp_for_ipsec_if(ifp);

			ipsec_cleanup_family(ifp, AF_INET);
			ipsec_cleanup_family(ifp, AF_INET6);

			lck_rw_unlock_exclusive(&pcb->ipsec_pcb_lock);

			ipsec_free_channels(&dc);

			ipsec_nexus_detach(pcb);

			/* Decrement refcnt to finish detaching and freeing */
			ifnet_decr_iorefcnt(ifp);
		} else
#endif // IPSEC_NEXUS
		{
			lck_rw_unlock_exclusive(&pcb->ipsec_pcb_lock);

#if IPSEC_NEXUS
			ipsec_free_channels(&dc);
#endif // IPSEC_NEXUS

			/*
			 * We want to do everything in our power to ensure that the interface
			 * really goes away when the socket is closed. We must remove IP/IPv6
			 * addresses and detach the protocols. Finally, we can remove and
			 * release the interface.
			 */
			key_delsp_for_ipsec_if(ifp);

			ipsec_cleanup_family(ifp, AF_INET);
			ipsec_cleanup_family(ifp, AF_INET6);

			/*
			 * Detach now; ipsec_detach() will be called asynchronously once
			 * the I/O reference count drops to 0.  There we will invoke
			 * ifnet_release().
			 */
			if ((result = ifnet_detach(ifp)) != 0) {
				os_log_error(OS_LOG_DEFAULT, "ipsec_ctl_disconnect - ifnet_detach failed: %d\n", result);
			}
		}
	} else {
		// Bound, but not connected
		lck_rw_unlock_exclusive(&pcb->ipsec_pcb_lock);
		ipsec_free_pcb(pcb, false);
	}

	return 0;
}

static errno_t
ipsec_ctl_send(__unused kern_ctl_ref    kctlref,
    __unused u_int32_t           unit,
    __unused void                        *unitinfo,
    mbuf_t                  m,
    __unused int                 flags)
{
	/* Receive messages from the control socket. Currently unused. */
	mbuf_freem(m);
	return 0;
}

static errno_t
ipsec_ctl_setopt(__unused kern_ctl_ref  kctlref,
    __unused u_int32_t             unit,
    void                                   *unitinfo,
    int                                            opt,
    void                                   *data,
    size_t                                 len)
{
	errno_t                                 result = 0;
	struct ipsec_pcb                        *pcb = unitinfo;
	if (pcb == NULL) {
		return EINVAL;
	}

	/* check for privileges for privileged options */
	switch (opt) {
	case IPSEC_OPT_FLAGS:
	case IPSEC_OPT_EXT_IFDATA_STATS:
	case IPSEC_OPT_SET_DELEGATE_INTERFACE:
	case IPSEC_OPT_OUTPUT_TRAFFIC_CLASS:
		if (kauth_cred_issuser(kauth_cred_get()) == 0) {
			return EPERM;
		}
		break;
	}

	switch (opt) {
	case IPSEC_OPT_FLAGS: {
		if (len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
		} else {
			pcb->ipsec_external_flags = *(u_int32_t *)data;
		}
		break;
	}

	case IPSEC_OPT_EXT_IFDATA_STATS: {
		if (len != sizeof(int)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp == NULL) {
			// Only can set after connecting
			result = EINVAL;
			break;
		}
		pcb->ipsec_ext_ifdata_stats = (*(int *)data) ? 1 : 0;
		break;
	}

	case IPSEC_OPT_INC_IFDATA_STATS_IN:
	case IPSEC_OPT_INC_IFDATA_STATS_OUT: {
		struct ipsec_stats_param *utsp = (struct ipsec_stats_param *)data;

		if (utsp == NULL || len < sizeof(struct ipsec_stats_param)) {
			result = EINVAL;
			break;
		}
		if (pcb->ipsec_ifp == NULL) {
			// Only can set after connecting
			result = EINVAL;
			break;
		}
		if (!pcb->ipsec_ext_ifdata_stats) {
			result = EINVAL;
			break;
		}
		if (opt == IPSEC_OPT_INC_IFDATA_STATS_IN) {
			ifnet_stat_increment_in(pcb->ipsec_ifp, utsp->utsp_packets,
			    utsp->utsp_bytes, utsp->utsp_errors);
		} else {
			ifnet_stat_increment_out(pcb->ipsec_ifp, utsp->utsp_packets,
			    utsp->utsp_bytes, utsp->utsp_errors);
		}
		break;
	}

	case IPSEC_OPT_SET_DELEGATE_INTERFACE: {
		ifnet_t del_ifp = NULL;
		char name[IFNAMSIZ];

		if (len > IFNAMSIZ - 1) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp == NULL) {
			// Only can set after connecting
			result = EINVAL;
			break;
		}
		if (len != 0) {                   /* if len==0, del_ifp will be NULL causing the delegate to be removed */
			bcopy(data, name, len);
			name[len] = 0;
			result = ifnet_find_by_name(name, &del_ifp);
		}
		if (result == 0) {
			os_log_error(OS_LOG_DEFAULT, "%s IPSEC_OPT_SET_DELEGATE_INTERFACE %s to %s\n",
			    __func__, pcb->ipsec_ifp->if_xname,
			    del_ifp ? del_ifp->if_xname : "NULL");

			result = ifnet_set_delegate(pcb->ipsec_ifp, del_ifp);
			if (del_ifp) {
				ifnet_release(del_ifp);
			}
		}
		break;
	}

	case IPSEC_OPT_OUTPUT_TRAFFIC_CLASS: {
		if (len != sizeof(int)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp == NULL) {
			// Only can set after connecting
			result = EINVAL;
			break;
		}
		mbuf_svc_class_t output_service_class = so_tc2msc(*(int *)data);
		if (output_service_class == MBUF_SC_UNSPEC) {
			pcb->ipsec_output_service_class = MBUF_SC_OAM;
		} else {
			pcb->ipsec_output_service_class = output_service_class;
		}
		os_log_error(OS_LOG_DEFAULT, "%s IPSEC_OPT_OUTPUT_TRAFFIC_CLASS %s svc %d\n",
		    __func__, pcb->ipsec_ifp->if_xname,
		    pcb->ipsec_output_service_class);
		break;
	}

#if IPSEC_NEXUS
	case IPSEC_OPT_ENABLE_CHANNEL: {
		if (len != sizeof(int)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp != NULL) {
			// Only can set before connecting
			result = EINVAL;
			break;
		}
		if ((*(int *)data) != 0 &&
		    (*(int *)data) != 1 &&
		    (*(int *)data) != IPSEC_IF_WMM_RING_COUNT) {
			result = EINVAL;
			break;
		}
		lck_rw_lock_exclusive(&pcb->ipsec_pcb_lock);
		pcb->ipsec_kpipe_count = *(int *)data;
		lck_rw_unlock_exclusive(&pcb->ipsec_pcb_lock);
		break;
	}

	case IPSEC_OPT_CHANNEL_BIND_PID: {
		if (len != sizeof(pid_t)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp != NULL) {
			// Only can set before connecting
			result = EINVAL;
			break;
		}
		lck_rw_lock_exclusive(&pcb->ipsec_pcb_lock);
		pcb->ipsec_kpipe_pid = *(pid_t *)data;
		lck_rw_unlock_exclusive(&pcb->ipsec_pcb_lock);
		break;
	}

	case IPSEC_OPT_ENABLE_FLOWSWITCH: {
		if (len != sizeof(int)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp == NULL) {
			// Only can set after connecting
			result = EINVAL;
			break;
		}
		if (!if_is_fsw_transport_netagent_enabled()) {
			result = ENOTSUP;
			break;
		}
		if (uuid_is_null(pcb->ipsec_nx.fsw_agent)) {
			result = ENOENT;
			break;
		}

		uint32_t flags = netagent_get_flags(pcb->ipsec_nx.fsw_agent);

		if (*(int *)data) {
			flags |= (NETAGENT_FLAG_NEXUS_PROVIDER |
			    NETAGENT_FLAG_NEXUS_LISTENER);
			result = netagent_set_flags(pcb->ipsec_nx.fsw_agent, flags);
			pcb->ipsec_needs_netagent = true;
		} else {
			pcb->ipsec_needs_netagent = false;
			flags &= ~(NETAGENT_FLAG_NEXUS_PROVIDER |
			    NETAGENT_FLAG_NEXUS_LISTENER);
			result = netagent_set_flags(pcb->ipsec_nx.fsw_agent, flags);
		}
		break;
	}

	case IPSEC_OPT_INPUT_FRAG_SIZE: {
		if (len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
			break;
		}
		u_int32_t input_frag_size = *(u_int32_t *)data;
		if (input_frag_size <= sizeof(struct ip6_hdr)) {
			pcb->ipsec_frag_size_set = FALSE;
			pcb->ipsec_input_frag_size = 0;
		} else {
			pcb->ipsec_frag_size_set = TRUE;
			pcb->ipsec_input_frag_size = input_frag_size;
		}
		break;
	}
	case IPSEC_OPT_ENABLE_NETIF: {
		if (len != sizeof(int)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp != NULL) {
			// Only can set before connecting
			result = EINVAL;
			break;
		}
		lck_rw_lock_exclusive(&pcb->ipsec_pcb_lock);
		pcb->ipsec_use_netif = !!(*(int *)data);
		lck_rw_unlock_exclusive(&pcb->ipsec_pcb_lock);
		break;
	}
	case IPSEC_OPT_SLOT_SIZE: {
		if (len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp != NULL) {
			// Only can set before connecting
			result = EINVAL;
			break;
		}
		u_int32_t slot_size = *(u_int32_t *)data;
		if (slot_size < IPSEC_IF_MIN_SLOT_SIZE ||
		    slot_size > IPSEC_IF_MAX_SLOT_SIZE) {
			return EINVAL;
		}
		pcb->ipsec_slot_size = slot_size;
		if (if_ipsec_debug != 0) {
			printf("%s: IPSEC_OPT_SLOT_SIZE %u\n", __func__, slot_size);
		}
		break;
	}
	case IPSEC_OPT_NETIF_RING_SIZE: {
		if (len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp != NULL) {
			// Only can set before connecting
			result = EINVAL;
			break;
		}
		u_int32_t ring_size = *(u_int32_t *)data;
		if (ring_size < IPSEC_IF_MIN_RING_SIZE ||
		    ring_size > IPSEC_IF_MAX_RING_SIZE) {
			return EINVAL;
		}
		pcb->ipsec_netif_ring_size = ring_size;
		if (if_ipsec_debug != 0) {
			printf("%s: IPSEC_OPT_NETIF_RING_SIZE %u\n", __func__, ring_size);
		}
		break;
	}
	case IPSEC_OPT_TX_FSW_RING_SIZE: {
		if (len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp != NULL) {
			// Only can set before connecting
			result = EINVAL;
			break;
		}
		u_int32_t ring_size = *(u_int32_t *)data;
		if (ring_size < IPSEC_IF_MIN_RING_SIZE ||
		    ring_size > IPSEC_IF_MAX_RING_SIZE) {
			return EINVAL;
		}
		pcb->ipsec_tx_fsw_ring_size = ring_size;
		if (if_ipsec_debug != 0) {
			printf("%s: IPSEC_OPT_TX_FSW_RING_SIZE %u\n", __func__, ring_size);
		}
		break;
	}
	case IPSEC_OPT_RX_FSW_RING_SIZE: {
		if (len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp != NULL) {
			// Only can set before connecting
			result = EINVAL;
			break;
		}
		u_int32_t ring_size = *(u_int32_t *)data;
		if (ring_size < IPSEC_IF_MIN_RING_SIZE ||
		    ring_size > IPSEC_IF_MAX_RING_SIZE) {
			return EINVAL;
		}
		pcb->ipsec_rx_fsw_ring_size = ring_size;
		if (if_ipsec_debug != 0) {
			printf("%s: IPSEC_OPT_TX_FSW_RING_SIZE %u\n", __func__, ring_size);
		}
		break;
	}
	case IPSEC_OPT_KPIPE_TX_RING_SIZE: {
		if (len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp != NULL) {
			// Only can set before connecting
			result = EINVAL;
			break;
		}
		u_int32_t ring_size = *(u_int32_t *)data;
		if (ring_size < IPSEC_IF_MIN_RING_SIZE ||
		    ring_size > IPSEC_IF_MAX_RING_SIZE) {
			return EINVAL;
		}
		pcb->ipsec_kpipe_tx_ring_size = ring_size;
		if (if_ipsec_debug != 0) {
			printf("%s: IPSEC_OPT_KPIPE_TX_RING_SIZE %u\n", __func__, ring_size);
		}
		break;
	}
	case IPSEC_OPT_KPIPE_RX_RING_SIZE: {
		if (len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
			break;
		}
		if (pcb->ipsec_ifp != NULL) {
			// Only can set before connecting
			result = EINVAL;
			break;
		}
		u_int32_t ring_size = *(u_int32_t *)data;
		if (ring_size < IPSEC_IF_MIN_RING_SIZE ||
		    ring_size > IPSEC_IF_MAX_RING_SIZE) {
			return EINVAL;
		}
		pcb->ipsec_kpipe_rx_ring_size = ring_size;
		if (if_ipsec_debug != 0) {
			printf("%s: IPSEC_OPT_KPIPE_RX_RING_SIZE %u\n", __func__, ring_size);
		}
		break;
	}

#endif // IPSEC_NEXUS

	default: {
		result = ENOPROTOOPT;
		break;
	}
	}

	return result;
}

static errno_t
ipsec_ctl_getopt(__unused kern_ctl_ref kctlref,
    __unused u_int32_t unit,
    void *unitinfo,
    int opt,
    void *data,
    size_t *len)
{
	errno_t result = 0;
	struct ipsec_pcb *pcb = unitinfo;
	if (pcb == NULL) {
		return EINVAL;
	}

	switch (opt) {
	case IPSEC_OPT_FLAGS: {
		if (*len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
		} else {
			*(u_int32_t *)data = pcb->ipsec_external_flags;
		}
		break;
	}

	case IPSEC_OPT_EXT_IFDATA_STATS: {
		if (*len != sizeof(int)) {
			result = EMSGSIZE;
		} else {
			*(int *)data = (pcb->ipsec_ext_ifdata_stats) ? 1 : 0;
		}
		break;
	}

	case IPSEC_OPT_IFNAME: {
		if (*len < MIN(strlen(pcb->ipsec_if_xname) + 1, sizeof(pcb->ipsec_if_xname))) {
			result = EMSGSIZE;
		} else {
			if (pcb->ipsec_ifp == NULL) {
				// Only can get after connecting
				result = EINVAL;
				break;
			}
			*len = scnprintf(data, *len, "%s", pcb->ipsec_if_xname) + 1;
		}
		break;
	}

	case IPSEC_OPT_OUTPUT_TRAFFIC_CLASS: {
		if (*len != sizeof(int)) {
			result = EMSGSIZE;
		} else {
			*(int *)data = so_svc2tc(pcb->ipsec_output_service_class);
		}
		break;
	}

#if IPSEC_NEXUS

	case IPSEC_OPT_ENABLE_CHANNEL: {
		if (*len != sizeof(int)) {
			result = EMSGSIZE;
		} else {
			lck_rw_lock_shared(&pcb->ipsec_pcb_lock);
			*(int *)data = pcb->ipsec_kpipe_count;
			lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		}
		break;
	}

	case IPSEC_OPT_CHANNEL_BIND_PID: {
		if (*len != sizeof(pid_t)) {
			result = EMSGSIZE;
		} else {
			lck_rw_lock_shared(&pcb->ipsec_pcb_lock);
			*(pid_t *)data = pcb->ipsec_kpipe_pid;
			lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		}
		break;
	}

	case IPSEC_OPT_ENABLE_FLOWSWITCH: {
		if (*len != sizeof(int)) {
			result = EMSGSIZE;
		} else {
			*(int *)data = if_check_netagent(pcb->ipsec_ifp, pcb->ipsec_nx.fsw_agent);
		}
		break;
	}

	case IPSEC_OPT_ENABLE_NETIF: {
		if (*len != sizeof(int)) {
			result = EMSGSIZE;
		} else {
			lck_rw_lock_shared(&pcb->ipsec_pcb_lock);
			*(int *)data = !!pcb->ipsec_use_netif;
			lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		}
		break;
	}

	case IPSEC_OPT_GET_CHANNEL_UUID: {
		lck_rw_lock_shared(&pcb->ipsec_pcb_lock);
		if (!ipsec_flag_isset(pcb, IPSEC_FLAGS_KPIPE_ALLOCATED)) {
			result = ENXIO;
		} else if (*len != sizeof(uuid_t) * pcb->ipsec_kpipe_count) {
			result = EMSGSIZE;
		} else {
			for (unsigned int i = 0; i < pcb->ipsec_kpipe_count; i++) {
				uuid_copy(((uuid_t *)data)[i], pcb->ipsec_kpipe_uuid[i]);
			}
		}
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
		break;
	}

	case IPSEC_OPT_INPUT_FRAG_SIZE: {
		if (*len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
		} else {
			*(u_int32_t *)data = pcb->ipsec_input_frag_size;
		}
		break;
	}
	case IPSEC_OPT_SLOT_SIZE: {
		if (*len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
		} else {
			*(u_int32_t *)data = pcb->ipsec_slot_size;
		}
		break;
	}
	case IPSEC_OPT_NETIF_RING_SIZE: {
		if (*len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
		} else {
			*(u_int32_t *)data = pcb->ipsec_netif_ring_size;
		}
		break;
	}
	case IPSEC_OPT_TX_FSW_RING_SIZE: {
		if (*len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
		} else {
			*(u_int32_t *)data = pcb->ipsec_tx_fsw_ring_size;
		}
		break;
	}
	case IPSEC_OPT_RX_FSW_RING_SIZE: {
		if (*len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
		} else {
			*(u_int32_t *)data = pcb->ipsec_rx_fsw_ring_size;
		}
		break;
	}
	case IPSEC_OPT_KPIPE_TX_RING_SIZE: {
		if (*len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
		} else {
			*(u_int32_t *)data = pcb->ipsec_kpipe_tx_ring_size;
		}
		break;
	}
	case IPSEC_OPT_KPIPE_RX_RING_SIZE: {
		if (*len != sizeof(u_int32_t)) {
			result = EMSGSIZE;
		} else {
			*(u_int32_t *)data = pcb->ipsec_kpipe_rx_ring_size;
		}
		break;
	}

#endif // IPSEC_NEXUS

	default: {
		result = ENOPROTOOPT;
		break;
	}
	}

	return result;
}

/* Network Interface functions */
static errno_t
ipsec_output(ifnet_t interface,
    mbuf_t data)
{
	struct ipsec_pcb *pcb = ifnet_softc(interface);
	struct ipsec_output_state ipsec_state;
	struct route ro;
	struct route_in6 ro6;
	int length;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct ip_out_args ipoa;
	struct ip6_out_args ip6oa;
	int error = 0;
	u_int ip_version = 0;
	int flags = 0;
	struct flowadv *adv = NULL;

	// Make sure this packet isn't looping through the interface
	if (necp_get_last_interface_index_from_packet(data) == interface->if_index) {
		error = EINVAL;
		goto ipsec_output_err;
	}

	// Mark the interface so NECP can evaluate tunnel policy
	necp_mark_packet_from_interface(data, interface);

	ip = mtod(data, struct ip *);
	ip_version = ip->ip_v;

	switch (ip_version) {
	case 4: {
#if IPSEC_NEXUS
		if (!pcb->ipsec_use_netif)
#endif // IPSEC_NEXUS
		{
			int af = AF_INET;
			bpf_tap_out(pcb->ipsec_ifp, DLT_NULL, data, &af, sizeof(af));
		}

		/* Apply encryption */
		memset(&ipsec_state, 0, sizeof(ipsec_state));
		ipsec_state.m = data;
		ipsec_state.dst = (struct sockaddr *)&ip->ip_dst;
		memset(&ipsec_state.ro, 0, sizeof(ipsec_state.ro));

		error = ipsec4_interface_output(&ipsec_state, interface);
		/* Tunneled in IPv6 - packet is gone */
		if (error == 0 && ipsec_state.tunneled == 6) {
			goto done;
		}

		data = ipsec_state.m;
		if (error || data == NULL) {
			if (error) {
				os_log_error(OS_LOG_DEFAULT, "ipsec_output: ipsec4_output error %d.\n", error);
			}
			goto ipsec_output_err;
		}

		/* Set traffic class, set flow */
		m_set_service_class(data, pcb->ipsec_output_service_class);
		data->m_pkthdr.pkt_flowsrc = FLOWSRC_IFNET;
		data->m_pkthdr.pkt_flowid = interface->if_flowhash;
		data->m_pkthdr.pkt_proto = ip->ip_p;
		data->m_pkthdr.pkt_flags = (PKTF_FLOW_ID | PKTF_FLOW_ADV | PKTF_FLOW_LOCALSRC);

		/* Flip endian-ness for ip_output */
		ip = mtod(data, struct ip *);
		NTOHS(ip->ip_len);
		NTOHS(ip->ip_off);

		/* Increment statistics */
		length = mbuf_pkthdr_len(data);
		ifnet_stat_increment_out(interface, 1, length, 0);

		/* Send to ip_output */
		memset(&ro, 0, sizeof(ro));

		flags = (IP_OUTARGS |   /* Passing out args to specify interface */
		    IP_NOIPSEC);                        /* To ensure the packet doesn't go through ipsec twice */

		memset(&ipoa, 0, sizeof(ipoa));
		ipoa.ipoa_flowadv.code = 0;
		ipoa.ipoa_flags = IPOAF_SELECT_SRCIF | IPOAF_BOUND_SRCADDR;
		if (ipsec_state.outgoing_if) {
			ipoa.ipoa_boundif = ipsec_state.outgoing_if;
			ipoa.ipoa_flags |= IPOAF_BOUND_IF;
		}
		ipsec_set_ipoa_for_interface(pcb->ipsec_ifp, &ipoa);

		adv = &ipoa.ipoa_flowadv;

		(void)ip_output(data, NULL, &ro, flags, NULL, &ipoa);
		data = NULL;

		if (adv->code == FADV_FLOW_CONTROLLED || adv->code == FADV_SUSPENDED) {
			error = ENOBUFS;
			ifnet_disable_output(interface);
		}

		goto done;
	}
	case 6: {
#if IPSEC_NEXUS
		if (!pcb->ipsec_use_netif)
#endif // IPSEC_NEXUS
		{
			int af = AF_INET6;
			bpf_tap_out(pcb->ipsec_ifp, DLT_NULL, data, &af, sizeof(af));
		}

		data = ipsec6_splithdr(data);
		if (data == NULL) {
			os_log_error(OS_LOG_DEFAULT, "ipsec_output: ipsec6_splithdr returned NULL\n");
			goto ipsec_output_err;
		}

		ip6 = mtod(data, struct ip6_hdr *);

		memset(&ipsec_state, 0, sizeof(ipsec_state));
		ipsec_state.m = data;
		ipsec_state.dst = (struct sockaddr *)&ip6->ip6_dst;
		memset(&ipsec_state.ro, 0, sizeof(ipsec_state.ro));

		error = ipsec6_interface_output(&ipsec_state, interface, &ip6->ip6_nxt, ipsec_state.m);
		if (error == 0 && ipsec_state.tunneled == 4) {          /* tunneled in IPv4 - packet is gone */
			goto done;
		}
		data = ipsec_state.m;
		if (error || data == NULL) {
			if (error) {
				os_log_error(OS_LOG_DEFAULT, "ipsec_output: ipsec6_output error %d\n", error);
			}
			goto ipsec_output_err;
		}

		/* Set traffic class, set flow */
		m_set_service_class(data, pcb->ipsec_output_service_class);
		data->m_pkthdr.pkt_flowsrc = FLOWSRC_IFNET;
		data->m_pkthdr.pkt_flowid = interface->if_flowhash;
		data->m_pkthdr.pkt_proto = ip6->ip6_nxt;
		data->m_pkthdr.pkt_flags = (PKTF_FLOW_ID | PKTF_FLOW_ADV | PKTF_FLOW_LOCALSRC);

		/* Increment statistics */
		length = mbuf_pkthdr_len(data);
		ifnet_stat_increment_out(interface, 1, length, 0);

		/* Send to ip6_output */
		memset(&ro6, 0, sizeof(ro6));

		flags = IPV6_OUTARGS;

		memset(&ip6oa, 0, sizeof(ip6oa));
		ip6oa.ip6oa_flowadv.code = 0;
		ip6oa.ip6oa_flags = IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_SRCADDR;
		if (ipsec_state.outgoing_if) {
			ip6oa.ip6oa_boundif = ipsec_state.outgoing_if;
			ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;
		}
		ipsec_set_ip6oa_for_interface(pcb->ipsec_ifp, &ip6oa);

		adv = &ip6oa.ip6oa_flowadv;

		(void) ip6_output(data, NULL, &ro6, flags, NULL, NULL, &ip6oa);
		data = NULL;

		if (adv->code == FADV_FLOW_CONTROLLED || adv->code == FADV_SUSPENDED) {
			error = ENOBUFS;
			ifnet_disable_output(interface);
		}

		goto done;
	}
	default: {
		os_log_error(OS_LOG_DEFAULT, "ipsec_output: Received unknown packet version %d.\n", ip_version);
		error = EINVAL;
		goto ipsec_output_err;
	}
	}

done:
	return error;

ipsec_output_err:
	if (data) {
		mbuf_freem(data);
	}
	goto done;
}

static void
ipsec_start(ifnet_t     interface)
{
	mbuf_t data;
	struct ipsec_pcb *pcb = ifnet_softc(interface);

	VERIFY(pcb != NULL);
	for (;;) {
		if (ifnet_dequeue(interface, &data) != 0) {
			break;
		}
		if (ipsec_output(interface, data) != 0) {
			break;
		}
	}
}

/* Network Interface functions */
static errno_t
ipsec_demux(__unused ifnet_t    interface,
    mbuf_t                          data,
    __unused char           *frame_header,
    protocol_family_t       *protocol)
{
	struct ip *ip;
	u_int ip_version;

	while (data != NULL && mbuf_len(data) < 1) {
		data = mbuf_next(data);
	}

	if (data == NULL) {
		return ENOENT;
	}

	ip = mtod(data, struct ip *);
	ip_version = ip->ip_v;

	switch (ip_version) {
	case 4:
		*protocol = PF_INET;
		return 0;
	case 6:
		*protocol = PF_INET6;
		return 0;
	default:
		break;
	}

	return 0;
}

static errno_t
ipsec_add_proto(__unused ifnet_t                                                interface,
    protocol_family_t                                               protocol,
    __unused const struct ifnet_demux_desc  *demux_array,
    __unused u_int32_t                                              demux_count)
{
	switch (protocol) {
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
ipsec_del_proto(__unused ifnet_t                        interface,
    __unused protocol_family_t      protocol)
{
	return 0;
}

static errno_t
ipsec_ioctl(ifnet_t interface,
    u_long command,
    void *data)
{
#if IPSEC_NEXUS
	struct ipsec_pcb *pcb = ifnet_softc(interface);
#endif
	errno_t result = 0;

	switch (command) {
	case SIOCSIFMTU: {
#if IPSEC_NEXUS
		if (pcb->ipsec_use_netif) {
			// Make sure we can fit packets in the channel buffers
			if (((uint64_t)((struct ifreq*)data)->ifr_mtu) > pcb->ipsec_slot_size) {
				result = EINVAL;
			} else {
				ifnet_set_mtu(interface, (uint32_t)((struct ifreq*)data)->ifr_mtu);
			}
		} else
#endif // IPSEC_NEXUS
		{
			ifnet_set_mtu(interface, ((struct ifreq*)data)->ifr_mtu);
		}
		break;
	}

	case SIOCSIFFLAGS:
		/* ifioctl() takes care of it */
		break;

	case SIOCSIFSUBFAMILY: {
		uint32_t subfamily;

		subfamily = ((struct ifreq*)data)->ifr_type.ift_subfamily;
		switch (subfamily) {
		case IFRTYPE_SUBFAMILY_BLUETOOTH:
			interface->if_subfamily = IFNET_SUBFAMILY_BLUETOOTH;
			break;
		case IFRTYPE_SUBFAMILY_WIFI:
			interface->if_subfamily = IFNET_SUBFAMILY_WIFI;
			break;
		case IFRTYPE_SUBFAMILY_QUICKRELAY:
			interface->if_subfamily = IFNET_SUBFAMILY_QUICKRELAY;
			break;
		case IFRTYPE_SUBFAMILY_DEFAULT:
			interface->if_subfamily = IFNET_SUBFAMILY_DEFAULT;
			break;
		default:
			result = EINVAL;
			break;
		}
		break;
	}

	default:
		result = EOPNOTSUPP;
	}

	return result;
}

static void
ipsec_detached(ifnet_t interface)
{
	struct ipsec_pcb *pcb = ifnet_softc(interface);

	(void)ifnet_release(interface);
	ipsec_free_pcb(pcb, true);
}

/* Protocol Handlers */

static errno_t
ipsec_proto_input(ifnet_t interface,
    protocol_family_t     protocol,
    mbuf_t m,
    __unused char *frame_header)
{
	mbuf_pkthdr_setrcvif(m, interface);

#if IPSEC_NEXUS
	struct ipsec_pcb *pcb = ifnet_softc(interface);
	if (!pcb->ipsec_use_netif)
#endif // IPSEC_NEXUS
	{
		uint32_t af = 0;
		struct ip *ip = mtod(m, struct ip *);
		if (ip->ip_v == 4) {
			af = AF_INET;
		} else if (ip->ip_v == 6) {
			af = AF_INET6;
		}
		bpf_tap_in(interface, DLT_NULL, m, &af, sizeof(af));
		pktap_input(interface, protocol, m, NULL);
	}

	int32_t pktlen = m->m_pkthdr.len;
	if (proto_input(protocol, m) != 0) {
		ifnet_stat_increment_in(interface, 0, 0, 1);
		m_freem(m);
	} else {
		ifnet_stat_increment_in(interface, 1, pktlen, 0);
	}

	return 0;
}

static errno_t
ipsec_proto_pre_output(__unused ifnet_t interface,
    protocol_family_t    protocol,
    __unused mbuf_t              *packet,
    __unused const struct sockaddr *dest,
    __unused void *route,
    __unused char *frame_type,
    __unused char *link_layer_dest)
{
	*(protocol_family_t *)(void *)frame_type = protocol;
	return 0;
}

static errno_t
ipsec_attach_proto(ifnet_t                              interface,
    protocol_family_t    protocol)
{
	struct ifnet_attach_proto_param proto;
	errno_t                                                 result;

	bzero(&proto, sizeof(proto));
	proto.input = ipsec_proto_input;
	proto.pre_output = ipsec_proto_pre_output;

	result = ifnet_attach_protocol(interface, protocol, &proto);
	if (result != 0 && result != EEXIST) {
		os_log_error(OS_LOG_DEFAULT, "ipsec_attach_inet - ifnet_attach_protocol %d failed: %d\n",
		    protocol, result);
	}

	return result;
}

errno_t
ipsec_inject_inbound_packet(ifnet_t     interface,
    mbuf_t      packet)
{
#if IPSEC_NEXUS
	struct ipsec_pcb *pcb = ifnet_softc(interface);

	if (pcb->ipsec_use_netif) {
		if (!ipsec_data_move_begin(pcb)) {
			os_log_info(OS_LOG_DEFAULT, "%s: data path stopped for %s\n", __func__,
			    if_name(pcb->ipsec_ifp));
			return ENXIO;
		}

		lck_rw_lock_shared(&pcb->ipsec_pcb_lock);

		lck_mtx_lock(&pcb->ipsec_input_chain_lock);

		if (pcb->ipsec_input_chain_count > (u_int32_t)if_ipsec_max_pending_input) {
			lck_mtx_unlock(&pcb->ipsec_input_chain_lock);
			lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);
			ipsec_data_move_end(pcb);
			return ENOSPC;
		}

		if (pcb->ipsec_input_chain != NULL) {
			pcb->ipsec_input_chain_last->m_nextpkt = packet;
		} else {
			pcb->ipsec_input_chain = packet;
		}
		pcb->ipsec_input_chain_count++;
		while (packet->m_nextpkt) {
			VERIFY(packet != packet->m_nextpkt);
			packet = packet->m_nextpkt;
			pcb->ipsec_input_chain_count++;
		}
		pcb->ipsec_input_chain_last = packet;
		lck_mtx_unlock(&pcb->ipsec_input_chain_lock);

		kern_channel_ring_t rx_ring = pcb->ipsec_netif_rxring[0];
		lck_rw_unlock_shared(&pcb->ipsec_pcb_lock);

		if (rx_ring != NULL) {
			kern_channel_notify(rx_ring, 0);
		}

		ipsec_data_move_end(pcb);
		return 0;
	} else
#endif // IPSEC_NEXUS
	{
		errno_t error;
		protocol_family_t protocol;
		if ((error = ipsec_demux(interface, packet, NULL, &protocol)) != 0) {
			return error;
		}

		return ipsec_proto_input(interface, protocol, packet, NULL);
	}
}

void
ipsec_set_pkthdr_for_interface(ifnet_t interface, mbuf_t packet, int family)
{
	if (packet != NULL && interface != NULL) {
		struct ipsec_pcb *pcb = ifnet_softc(interface);
		if (pcb != NULL) {
			/* Set traffic class, set flow */
			m_set_service_class(packet, pcb->ipsec_output_service_class);
			packet->m_pkthdr.pkt_flowsrc = FLOWSRC_IFNET;
			packet->m_pkthdr.pkt_flowid = interface->if_flowhash;
			if (family == AF_INET) {
				struct ip *ip = mtod(packet, struct ip *);
				packet->m_pkthdr.pkt_proto = ip->ip_p;
			} else if (family == AF_INET6) {
				struct ip6_hdr *ip6 = mtod(packet, struct ip6_hdr *);
				packet->m_pkthdr.pkt_proto = ip6->ip6_nxt;
			}
			packet->m_pkthdr.pkt_flags = (PKTF_FLOW_ID | PKTF_FLOW_ADV | PKTF_FLOW_LOCALSRC);
		}
	}
}

void
ipsec_set_ipoa_for_interface(ifnet_t interface, struct ip_out_args *ipoa)
{
	struct ipsec_pcb *pcb;

	if (interface == NULL || ipoa == NULL) {
		return;
	}
	pcb = ifnet_softc(interface);

	if (net_qos_policy_restricted == 0) {
		ipoa->ipoa_flags |= IPOAF_QOSMARKING_ALLOWED;
		ipoa->ipoa_sotc = so_svc2tc(pcb->ipsec_output_service_class);
	} else if (pcb->ipsec_output_service_class != MBUF_SC_VO ||
	    net_qos_policy_restrict_avapps != 0) {
		ipoa->ipoa_flags &= ~IPOAF_QOSMARKING_ALLOWED;
	} else {
		ipoa->ipoa_flags |= IP6OAF_QOSMARKING_ALLOWED;
		ipoa->ipoa_sotc = SO_TC_VO;
	}
}

void
ipsec_set_ip6oa_for_interface(ifnet_t interface, struct ip6_out_args *ip6oa)
{
	struct ipsec_pcb *pcb;

	if (interface == NULL || ip6oa == NULL) {
		return;
	}
	pcb = ifnet_softc(interface);

	if (net_qos_policy_restricted == 0) {
		ip6oa->ip6oa_flags |= IPOAF_QOSMARKING_ALLOWED;
		ip6oa->ip6oa_sotc = so_svc2tc(pcb->ipsec_output_service_class);
	} else if (pcb->ipsec_output_service_class != MBUF_SC_VO ||
	    net_qos_policy_restrict_avapps != 0) {
		ip6oa->ip6oa_flags &= ~IPOAF_QOSMARKING_ALLOWED;
	} else {
		ip6oa->ip6oa_flags |= IP6OAF_QOSMARKING_ALLOWED;
		ip6oa->ip6oa_sotc = SO_TC_VO;
	}
}


static void
ipsec_data_move_drain(struct ipsec_pcb *pcb)
{
	lck_mtx_lock(&pcb->ipsec_pcb_data_move_lock);
	/* data path must already be marked as not ready */
	VERIFY(!IPSEC_IS_DATA_PATH_READY(pcb));
	pcb->ipsec_pcb_drainers++;
	while (pcb->ipsec_pcb_data_move != 0) {
		(void)msleep(&(pcb->ipsec_pcb_data_move), &pcb->ipsec_pcb_data_move_lock,
		    (PZERO - 1), __func__, NULL);
	}
	VERIFY(!IPSEC_IS_DATA_PATH_READY(pcb));
	VERIFY(pcb->ipsec_pcb_drainers > 0);
	pcb->ipsec_pcb_drainers--;
	lck_mtx_unlock(&pcb->ipsec_pcb_data_move_lock);
}

static void
ipsec_wait_data_move_drain(struct ipsec_pcb *pcb)
{
	/*
	 * Mark the data path as not usable.
	 */
	lck_mtx_lock(&pcb->ipsec_pcb_data_move_lock);
	IPSEC_CLR_DATA_PATH_READY(pcb);
	lck_mtx_unlock(&pcb->ipsec_pcb_data_move_lock);

	/* Wait until all threads in the data paths are done. */
	ipsec_data_move_drain(pcb);
}
