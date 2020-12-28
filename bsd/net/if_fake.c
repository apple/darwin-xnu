/*
 * Copyright (c) 2015-2019 Apple Inc. All rights reserved.
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

/*
 * if_fake.c
 * - fake network interface used for testing
 * - "feth" (e.g. "feth0", "feth1") is a virtual ethernet interface that allows
 *   two instances to have their output/input paths "crossed-over" so that
 *   output on one is input on the other
 */

/*
 * Modification History:
 *
 * September 9, 2015	Dieter Siegmund (dieter@apple.com)
 * - created
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/kern_event.h>
#include <sys/mcache.h>
#include <sys/syslog.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_vlan_var.h>
#include <net/if_fake_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_types.h>
#include <libkern/OSAtomic.h>

#include <net/dlil.h>

#include <net/kpi_interface.h>
#include <net/kpi_protocol.h>

#include <kern/locks.h>
#include <kern/zalloc.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/if_ether.h>
#endif

#include <net/if_media.h>
#include <net/ether_if_module.h>

static boolean_t
is_power_of_two(unsigned int val)
{
	return (val & (val - 1)) == 0;
}

#define FAKE_ETHER_NAME         "feth"

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, OID_AUTO, fake, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "Fake interface");

static int if_fake_txstart = 1;
SYSCTL_INT(_net_link_fake, OID_AUTO, txstart, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_txstart, 0, "Fake interface TXSTART mode");

static int if_fake_hwcsum = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, hwcsum, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_hwcsum, 0, "Fake interface simulate hardware checksum");

static int if_fake_nxattach = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, nxattach, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_nxattach, 0, "Fake interface auto-attach nexus");

static int if_fake_bsd_mode = 1;
SYSCTL_INT(_net_link_fake, OID_AUTO, bsd_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_bsd_mode, 0, "Fake interface attach as BSD interface");

static int if_fake_debug = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_debug, 0, "Fake interface debug logs");

static int if_fake_wmm_mode = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, wmm_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_wmm_mode, 0, "Fake interface in 802.11 WMM mode");

static int if_fake_multibuflet = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, multibuflet, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_multibuflet, 0, "Fake interface using multi-buflet packets");

static int if_fake_copypkt_mode = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, copypkt_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_copypkt_mode, 0, "Fake interface copying packet to peer");

/* sysctl net.link.fake.tx_headroom */
#define FETH_TX_HEADROOM_MAX      32
static unsigned int if_fake_tx_headroom = 0;

static int
feth_tx_headroom_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_tx_headroom,
	    sizeof(if_fake_tx_headroom), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > FETH_TX_HEADROOM_MAX ||
		    (new_value % 8) != 0) {
			return EINVAL;
		}
		if_fake_tx_headroom = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, tx_headroom,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, feth_tx_headroom_sysctl, "IU", "Fake ethernet Tx headroom");


/* sysctl net.link.fake.max_mtu */
#define FETH_MAX_MTU_DEFAULT    2048
#define FETH_MAX_MTU_MAX        ((16 * 1024) - ETHER_HDR_LEN)

static unsigned int if_fake_max_mtu = FETH_MAX_MTU_DEFAULT;

/* sysctl net.link.fake.buflet_size */
#define FETH_BUFLET_SIZE_MIN            512
#define FETH_BUFLET_SIZE_MAX            2048

static unsigned int if_fake_buflet_size = FETH_BUFLET_SIZE_MIN;

static int
feth_max_mtu_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_max_mtu,
	    sizeof(if_fake_max_mtu), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > FETH_MAX_MTU_MAX ||
		    new_value < ETHERMTU ||
		    new_value <= if_fake_buflet_size) {
			return EINVAL;
		}
		if_fake_max_mtu = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, max_mtu,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, feth_max_mtu_sysctl, "IU", "Fake interface maximum MTU");

static int
feth_buflet_size_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_buflet_size,
	    sizeof(if_fake_buflet_size), &new_value, &changed);
	if (error == 0 && changed != 0) {
		/* must be a power of 2 between min and max */
		if (new_value > FETH_BUFLET_SIZE_MAX ||
		    new_value < FETH_BUFLET_SIZE_MIN ||
		    !is_power_of_two(new_value) ||
		    new_value >= if_fake_max_mtu) {
			return EINVAL;
		}
		if_fake_buflet_size = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, buflet_size,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, feth_buflet_size_sysctl, "IU", "Fake interface buflet size");

static unsigned int if_fake_user_access = 0;

static int
feth_user_access_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_user_access,
	    sizeof(if_fake_user_access), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value != 0) {
			if (new_value != 1) {
				return EINVAL;
			}
			/*
			 * copypkt mode requires a kernel only buffer pool so
			 * it is incompatible with user access mode.
			 */
			if (if_fake_copypkt_mode != 0) {
				return ENOTSUP;
			}
		}
		if_fake_user_access = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, user_access,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, feth_user_access_sysctl, "IU", "Fake interface user access");

/* sysctl net.link.fake.if_adv_intvl (unit: millisecond) */
#define FETH_IF_ADV_INTVL_MIN            10
#define FETH_IF_ADV_INTVL_MAX            INT_MAX

static int if_fake_if_adv_interval = 0; /* no interface advisory */
static int
feth_if_adv_interval_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_if_adv_interval,
	    sizeof(if_fake_if_adv_interval), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if ((new_value != 0) && (new_value > FETH_IF_ADV_INTVL_MAX ||
		    new_value < FETH_IF_ADV_INTVL_MIN)) {
			return EINVAL;
		}
		if_fake_if_adv_interval = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, if_adv_intvl,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    feth_if_adv_interval_sysctl, "IU",
    "Fake interface will generate interface advisories reports at the specified interval in ms");

/* sysctl net.link.fake.tx_drops */
/*
 * Fake ethernet will drop packet on the transmit path at the specified
 * rate, i.e drop one in every if_fake_tx_drops number of packets.
 */
#define FETH_TX_DROPS_MIN            0
#define FETH_TX_DROPS_MAX            INT_MAX
static int if_fake_tx_drops = 0; /* no packets are dropped */
static int
feth_fake_tx_drops_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_tx_drops,
	    sizeof(if_fake_tx_drops), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > FETH_TX_DROPS_MAX ||
		    new_value < FETH_TX_DROPS_MIN) {
			return EINVAL;
		}
		if_fake_tx_drops = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, tx_drops,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    feth_fake_tx_drops_sysctl, "IU",
    "Fake interface will intermittently drop packets on Tx path");

/**
** virtual ethernet structures, types
**/

#define IFF_NUM_TX_RINGS_WMM_MODE       4
#define IFF_NUM_RX_RINGS_WMM_MODE       1
#define IFF_MAX_TX_RINGS        IFF_NUM_TX_RINGS_WMM_MODE
#define IFF_MAX_RX_RINGS        IFF_NUM_RX_RINGS_WMM_MODE

typedef uint16_t        iff_flags_t;
#define IFF_FLAGS_HWCSUM                0x0001
#define IFF_FLAGS_BSD_MODE              0x0002
#define IFF_FLAGS_DETACHING             0x0004
#define IFF_FLAGS_WMM_MODE              0x0008
#define IFF_FLAGS_MULTIBUFLETS          0x0010
#define IFF_FLAGS_COPYPKT_MODE          0x0020


struct if_fake {
	char                    iff_name[IFNAMSIZ]; /* our unique id */
	ifnet_t                 iff_ifp;
	iff_flags_t             iff_flags;
	uint32_t                iff_retain_count;
	ifnet_t                 iff_peer;       /* the other end */
	int                     iff_media_current;
	int                     iff_media_active;
	uint32_t                iff_media_count;
	int                     iff_media_list[IF_FAKE_MEDIA_LIST_MAX];
	struct mbuf *           iff_pending_tx_packet;
	boolean_t               iff_start_busy;
	unsigned int            iff_max_mtu;
};

typedef struct if_fake * if_fake_ref;

static if_fake_ref
ifnet_get_if_fake(ifnet_t ifp);

#define FETH_DPRINTF(fmt, ...)                                  \
	{ if (if_fake_debug != 0) printf("%s " fmt, __func__, ## __VA_ARGS__); }

static inline boolean_t
feth_in_bsd_mode(if_fake_ref fakeif)
{
	return (fakeif->iff_flags & IFF_FLAGS_BSD_MODE) != 0;
}

static inline void
feth_set_detaching(if_fake_ref fakeif)
{
	fakeif->iff_flags |= IFF_FLAGS_DETACHING;
}

static inline boolean_t
feth_is_detaching(if_fake_ref fakeif)
{
	return (fakeif->iff_flags & IFF_FLAGS_DETACHING) != 0;
}

static int
feth_enable_dequeue_stall(ifnet_t ifp, uint32_t enable)
{
	int error;

	if (enable != 0) {
		error = ifnet_disable_output(ifp);
	} else {
		error = ifnet_enable_output(ifp);
	}

	return error;
}


#define FETH_MAXUNIT    IF_MAXUNIT
#define FETH_ZONE_MAX_ELEM      MIN(IFNETS_MAX, FETH_MAXUNIT)
#define M_FAKE          M_DEVBUF

static  int feth_clone_create(struct if_clone *, u_int32_t, void *);
static  int feth_clone_destroy(ifnet_t);
static  int feth_output(ifnet_t ifp, struct mbuf *m);
static  void feth_start(ifnet_t ifp);
static  int feth_ioctl(ifnet_t ifp, u_long cmd, void * addr);
static  int feth_config(ifnet_t ifp, ifnet_t peer);
static  void feth_if_free(ifnet_t ifp);
static  void feth_ifnet_set_attrs(if_fake_ref fakeif, ifnet_t ifp);
static  void feth_free(if_fake_ref fakeif);

static struct if_clone
    feth_cloner = IF_CLONE_INITIALIZER(FAKE_ETHER_NAME,
    feth_clone_create,
    feth_clone_destroy,
    0,
    FETH_MAXUNIT,
    FETH_ZONE_MAX_ELEM,
    sizeof(struct if_fake));
static  void interface_link_event(ifnet_t ifp, u_int32_t event_code);

/* some media words to pretend to be ethernet */
static int default_media_words[] = {
	IFM_MAKEWORD(IFM_ETHER, 0, 0, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_10G_T, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_2500_T, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_5000_T, IFM_FDX, 0),

	IFM_MAKEWORD(IFM_ETHER, IFM_10G_KX4, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_20G_KR2, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_2500_SX, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_25G_KR, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_40G_SR4, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_50G_CR2, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_56G_R4, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_100G_CR4, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_400G_AUI8, IFM_FDX, 0),
};
#define default_media_words_count (sizeof(default_media_words)          \
	                           / sizeof (default_media_words[0]))

/**
** veth locks
**/
static inline lck_grp_t *
my_lck_grp_alloc_init(const char * grp_name)
{
	lck_grp_t *             grp;
	lck_grp_attr_t *        grp_attrs;

	grp_attrs = lck_grp_attr_alloc_init();
	grp = lck_grp_alloc_init(grp_name, grp_attrs);
	lck_grp_attr_free(grp_attrs);
	return grp;
}

static inline lck_mtx_t *
my_lck_mtx_alloc_init(lck_grp_t * lck_grp)
{
	lck_attr_t *    lck_attrs;
	lck_mtx_t *             lck_mtx;

	lck_attrs = lck_attr_alloc_init();
	lck_mtx = lck_mtx_alloc_init(lck_grp, lck_attrs);
	lck_attr_free(lck_attrs);
	return lck_mtx;
}

static lck_mtx_t *      feth_lck_mtx;

static inline void
feth_lock_init(void)
{
	lck_grp_t *             feth_lck_grp;

	feth_lck_grp = my_lck_grp_alloc_init("fake");
	feth_lck_mtx = my_lck_mtx_alloc_init(feth_lck_grp);
}

#if 0
static inline void
feth_assert_lock_not_held(void)
{
	LCK_MTX_ASSERT(feth_lck_mtx, LCK_MTX_ASSERT_NOTOWNED);
	return;
}
#endif

static inline void
feth_lock(void)
{
	lck_mtx_lock(feth_lck_mtx);
	return;
}

static inline void
feth_unlock(void)
{
	lck_mtx_unlock(feth_lck_mtx);
	return;
}

static inline int
get_max_mtu(int bsd_mode, unsigned int max_mtu)
{
	unsigned int    mtu;

	if (bsd_mode != 0) {
		mtu = (njcl > 0) ? (M16KCLBYTES - ETHER_HDR_LEN)
		    : MBIGCLBYTES - ETHER_HDR_LEN;
		if (mtu > max_mtu) {
			mtu = max_mtu;
		}
	} else {
		mtu = max_mtu;
	}
	return mtu;
}

static inline unsigned int
feth_max_mtu(ifnet_t ifp)
{
	if_fake_ref     fakeif;
	unsigned int    max_mtu = ETHERMTU;

	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif != NULL) {
		max_mtu = fakeif->iff_max_mtu;
	}
	feth_unlock();
	return max_mtu;
}

static void
feth_free(if_fake_ref fakeif)
{
	assert(fakeif->iff_retain_count == 0);
	if (feth_in_bsd_mode(fakeif)) {
		if (fakeif->iff_pending_tx_packet) {
			m_freem(fakeif->iff_pending_tx_packet);
		}
	}

	FETH_DPRINTF("%s\n", fakeif->iff_name);
	if_clone_softc_deallocate(&feth_cloner, fakeif);
}

static void
feth_release(if_fake_ref fakeif)
{
	u_int32_t               old_retain_count;

	old_retain_count = OSDecrementAtomic(&fakeif->iff_retain_count);
	switch (old_retain_count) {
	case 0:
		assert(old_retain_count != 0);
		break;
	case 1:
		feth_free(fakeif);
		break;
	default:
		break;
	}
	return;
}


/**
** feth interface routines
**/
static void
feth_ifnet_set_attrs(if_fake_ref fakeif, ifnet_t ifp)
{
	(void)ifnet_set_capabilities_enabled(ifp, 0, -1);
	ifnet_set_addrlen(ifp, ETHER_ADDR_LEN);
	ifnet_set_baudrate(ifp, 0);
	ifnet_set_mtu(ifp, ETHERMTU);
	ifnet_set_flags(ifp,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    0xffff);
	ifnet_set_hdrlen(ifp, sizeof(struct ether_header));
	if ((fakeif->iff_flags & IFF_FLAGS_HWCSUM) != 0) {
		ifnet_set_offload(ifp,
		    IFNET_CSUM_IP | IFNET_CSUM_TCP | IFNET_CSUM_UDP |
		    IFNET_CSUM_TCPIPV6 | IFNET_CSUM_UDPIPV6);
	} else {
		ifnet_set_offload(ifp, 0);
	}
}

static void
interface_link_event(ifnet_t ifp, u_int32_t event_code)
{
	struct {
		struct kern_event_msg   header;
		u_int32_t               unit;
		char                    if_name[IFNAMSIZ];
	} event;

	bzero(&event, sizeof(event));
	event.header.total_size    = sizeof(event);
	event.header.vendor_code   = KEV_VENDOR_APPLE;
	event.header.kev_class     = KEV_NETWORK_CLASS;
	event.header.kev_subclass  = KEV_DL_SUBCLASS;
	event.header.event_code    = event_code;
	event.header.event_data[0] = ifnet_family(ifp);
	event.unit                 = (u_int32_t) ifnet_unit(ifp);
	strlcpy(event.if_name, ifnet_name(ifp), IFNAMSIZ);
	ifnet_event(ifp, &event.header);
	return;
}

static if_fake_ref
ifnet_get_if_fake(ifnet_t ifp)
{
	return (if_fake_ref)ifnet_softc(ifp);
}

static int
feth_clone_create(struct if_clone *ifc, u_int32_t unit, __unused void *params)
{
	int                             error;
	if_fake_ref                     fakeif;
	struct ifnet_init_eparams       feth_init;
	ifnet_t                         ifp;
	uint8_t                         mac_address[ETHER_ADDR_LEN];

	fakeif = if_clone_softc_allocate(&feth_cloner);
	if (fakeif == NULL) {
		return ENOBUFS;
	}
	fakeif->iff_retain_count = 1;
#define FAKE_ETHER_NAME_LEN     (sizeof(FAKE_ETHER_NAME) - 1)
	_CASSERT(FAKE_ETHER_NAME_LEN == 4);
	bcopy(FAKE_ETHER_NAME, mac_address, FAKE_ETHER_NAME_LEN);
	mac_address[ETHER_ADDR_LEN - 2] = (unit & 0xff00) >> 8;
	mac_address[ETHER_ADDR_LEN - 1] = unit & 0xff;
	if (if_fake_bsd_mode != 0) {
		fakeif->iff_flags |= IFF_FLAGS_BSD_MODE;
	}
	if (if_fake_hwcsum != 0) {
		fakeif->iff_flags |= IFF_FLAGS_HWCSUM;
	}
	fakeif->iff_max_mtu = get_max_mtu(if_fake_bsd_mode, if_fake_max_mtu);

	/* use the interface name as the unique id for ifp recycle */
	if ((unsigned int)
	    snprintf(fakeif->iff_name, sizeof(fakeif->iff_name), "%s%d",
	    ifc->ifc_name, unit) >= sizeof(fakeif->iff_name)) {
		feth_release(fakeif);
		return EINVAL;
	}
	bzero(&feth_init, sizeof(feth_init));
	feth_init.ver = IFNET_INIT_CURRENT_VERSION;
	feth_init.len = sizeof(feth_init);
	if (feth_in_bsd_mode(fakeif)) {
		if (if_fake_txstart != 0) {
			feth_init.start = feth_start;
		} else {
			feth_init.flags |= IFNET_INIT_LEGACY;
			feth_init.output = feth_output;
		}
	}
	if (if_fake_nxattach == 0) {
		feth_init.flags |= IFNET_INIT_NX_NOAUTO;
	}
	feth_init.uniqueid = fakeif->iff_name;
	feth_init.uniqueid_len = strlen(fakeif->iff_name);
	feth_init.name = ifc->ifc_name;
	feth_init.unit = unit;
	feth_init.family = IFNET_FAMILY_ETHERNET;
	feth_init.type = IFT_ETHER;
	feth_init.demux = ether_demux;
	feth_init.add_proto = ether_add_proto;
	feth_init.del_proto = ether_del_proto;
	feth_init.check_multi = ether_check_multi;
	feth_init.framer_extended = ether_frameout_extended;
	feth_init.softc = fakeif;
	feth_init.ioctl = feth_ioctl;
	feth_init.set_bpf_tap = NULL;
	feth_init.detach = feth_if_free;
	feth_init.broadcast_addr = etherbroadcastaddr;
	feth_init.broadcast_len = ETHER_ADDR_LEN;
	if (feth_in_bsd_mode(fakeif)) {
		error = ifnet_allocate_extended(&feth_init, &ifp);
		if (error) {
			feth_release(fakeif);
			return error;
		}
		feth_ifnet_set_attrs(fakeif, ifp);
	}
	fakeif->iff_media_count = MIN(default_media_words_count, IF_FAKE_MEDIA_LIST_MAX);
	bcopy(default_media_words, fakeif->iff_media_list,
	    fakeif->iff_media_count * sizeof(fakeif->iff_media_list[0]));
	if (feth_in_bsd_mode(fakeif)) {
		error = ifnet_attach(ifp, NULL);
		if (error) {
			ifnet_release(ifp);
			feth_release(fakeif);
			return error;
		}
		fakeif->iff_ifp = ifp;
	}

	ifnet_set_lladdr(ifp, mac_address, sizeof(mac_address));

	/* attach as ethernet */
	bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
	return 0;
}

static int
feth_clone_destroy(ifnet_t ifp)
{
	if_fake_ref     fakeif;

	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif == NULL || feth_is_detaching(fakeif)) {
		feth_unlock();
		return 0;
	}
	feth_set_detaching(fakeif);
	feth_unlock();

	feth_config(ifp, NULL);
	ifnet_detach(ifp);
	return 0;
}

static void
feth_enqueue_input(ifnet_t ifp, struct mbuf * m)
{
	struct ifnet_stat_increment_param stats = {};

	stats.packets_in = 1;
	stats.bytes_in = (uint32_t)mbuf_pkthdr_len(m) + ETHER_HDR_LEN;
	ifnet_input(ifp, m, &stats);
}

static struct mbuf *
copy_mbuf(struct mbuf *m)
{
	struct mbuf *   copy_m;
	uint32_t        pkt_len;
	uint32_t        offset;

	if ((m->m_flags & M_PKTHDR) == 0) {
		return NULL;
	}
	pkt_len = m->m_pkthdr.len;
	MGETHDR(copy_m, M_DONTWAIT, MT_DATA);
	if (copy_m == NULL) {
		goto failed;
	}
	if (pkt_len > MHLEN) {
		if (pkt_len <= MCLBYTES) {
			MCLGET(copy_m, M_DONTWAIT);
		} else if (pkt_len <= MBIGCLBYTES) {
			copy_m = m_mbigget(copy_m, M_DONTWAIT);
		} else if (pkt_len <= M16KCLBYTES && njcl > 0) {
			copy_m = m_m16kget(copy_m, M_DONTWAIT);
		} else {
			printf("if_fake: copy_mbuf(): packet too large %d\n",
			    pkt_len);
			goto failed;
		}
		if (copy_m == NULL || (copy_m->m_flags & M_EXT) == 0) {
			goto failed;
		}
	}
	mbuf_setlen(copy_m, pkt_len);
	copy_m->m_pkthdr.len = pkt_len;
	copy_m->m_pkthdr.pkt_svc = m->m_pkthdr.pkt_svc;
	offset = 0;
	while (m != NULL && offset < pkt_len) {
		uint32_t        frag_len;

		frag_len = m->m_len;
		if (frag_len > (pkt_len - offset)) {
			printf("if_fake_: Large mbuf fragment %d > %d\n",
			    frag_len, (pkt_len - offset));
			goto failed;
		}
		m_copydata(m, 0, frag_len, mtod(copy_m, void *) + offset);
		offset += frag_len;
		m = m->m_next;
	}
	return copy_m;

failed:
	if (copy_m != NULL) {
		m_freem(copy_m);
	}
	return NULL;
}

static void
feth_output_common(ifnet_t ifp, struct mbuf * m, ifnet_t peer,
    iff_flags_t flags)
{
	void *          frame_header;

	frame_header = mbuf_data(m);
	if ((flags & IFF_FLAGS_HWCSUM) != 0) {
		m->m_pkthdr.csum_data = 0xffff;
		m->m_pkthdr.csum_flags =
		    CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
		    CSUM_IP_CHECKED | CSUM_IP_VALID;
	}

	(void)ifnet_stat_increment_out(ifp, 1, m->m_pkthdr.len, 0);
	bpf_tap_out(ifp, DLT_EN10MB, m, NULL, 0);

	(void)mbuf_pkthdr_setrcvif(m, peer);
	mbuf_pkthdr_setheader(m, frame_header);
	mbuf_pkthdr_adjustlen(m, -ETHER_HDR_LEN);
	(void)mbuf_setdata(m, (char *)mbuf_data(m) + ETHER_HDR_LEN,
	    mbuf_len(m) - ETHER_HDR_LEN);
	bpf_tap_in(peer, DLT_EN10MB, m, frame_header,
	    sizeof(struct ether_header));
	feth_enqueue_input(peer, m);
}

static void
feth_start(ifnet_t ifp)
{
	struct mbuf *   copy_m = NULL;
	if_fake_ref     fakeif;
	iff_flags_t     flags = 0;
	ifnet_t peer = NULL;
	struct mbuf *   m;
	struct mbuf *   save_m;

	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif == NULL) {
		feth_unlock();
		return;
	}

	if (fakeif->iff_start_busy) {
		feth_unlock();
		printf("if_fake: start is busy\n");
		return;
	}

	peer = fakeif->iff_peer;
	flags = fakeif->iff_flags;

	/* check for pending TX */
	m = fakeif->iff_pending_tx_packet;
	if (m != NULL) {
		if (peer != NULL) {
			copy_m = copy_mbuf(m);
			if (copy_m == NULL) {
				feth_unlock();
				return;
			}
		}
		fakeif->iff_pending_tx_packet = NULL;
		m_freem(m);
		m = NULL;
	}
	fakeif->iff_start_busy = TRUE;
	feth_unlock();
	save_m = NULL;
	for (;;) {
		if (copy_m != NULL) {
			assert(peer != NULL);
			feth_output_common(ifp, copy_m, peer, flags);
			copy_m = NULL;
		}
		if (ifnet_dequeue(ifp, &m) != 0) {
			break;
		}
		if (peer == NULL) {
			m_freem(m);
		} else {
			copy_m = copy_mbuf(m);
			if (copy_m == NULL) {
				save_m = m;
				break;
			}
			m_freem(m);
		}
	}
	peer = NULL;
	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif != NULL) {
		fakeif->iff_start_busy = FALSE;
		if (save_m != NULL && fakeif->iff_peer != NULL) {
			/* save it for next time */
			fakeif->iff_pending_tx_packet = save_m;
			save_m = NULL;
		}
	}
	feth_unlock();
	if (save_m != NULL) {
		/* didn't save packet, so free it */
		m_freem(save_m);
	}
}

static int
feth_output(ifnet_t ifp, struct mbuf * m)
{
	struct mbuf *           copy_m;
	if_fake_ref             fakeif;
	iff_flags_t             flags;
	ifnet_t         peer = NULL;

	if (m == NULL) {
		return 0;
	}
	copy_m = copy_mbuf(m);
	m_freem(m);
	m = NULL;
	if (copy_m == NULL) {
		/* count this as an output error */
		ifnet_stat_increment_out(ifp, 0, 0, 1);
		return 0;
	}
	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif != NULL) {
		peer = fakeif->iff_peer;
		flags = fakeif->iff_flags;
	}
	feth_unlock();
	if (peer == NULL) {
		m_freem(copy_m);
		ifnet_stat_increment_out(ifp, 0, 0, 1);
		return 0;
	}
	feth_output_common(ifp, copy_m, peer, flags);
	return 0;
}

static int
feth_config(ifnet_t ifp, ifnet_t peer)
{
	int             connected = FALSE;
	int             disconnected = FALSE;
	int             error = 0;
	if_fake_ref     fakeif = NULL;

	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif == NULL) {
		error = EINVAL;
		goto done;
	}
	if (peer != NULL) {
		/* connect to peer */
		if_fake_ref     peer_fakeif;

		peer_fakeif = ifnet_get_if_fake(peer);
		if (peer_fakeif == NULL) {
			error = EINVAL;
			goto done;
		}
		if (feth_is_detaching(fakeif) ||
		    feth_is_detaching(peer_fakeif) ||
		    peer_fakeif->iff_peer != NULL ||
		    fakeif->iff_peer != NULL) {
			error = EBUSY;
			goto done;
		}
		fakeif->iff_peer = peer;
		peer_fakeif->iff_peer = ifp;
		connected = TRUE;
	} else if (fakeif->iff_peer != NULL) {
		/* disconnect from peer */
		if_fake_ref     peer_fakeif;

		peer = fakeif->iff_peer;
		peer_fakeif = ifnet_get_if_fake(peer);
		if (peer_fakeif == NULL) {
			/* should not happen */
			error = EINVAL;
			goto done;
		}
		fakeif->iff_peer = NULL;
		peer_fakeif->iff_peer = NULL;
		disconnected = TRUE;
	}

done:
	feth_unlock();

	/* generate link status event if we connect or disconnect */
	if (connected) {
		interface_link_event(ifp, KEV_DL_LINK_ON);
		interface_link_event(peer, KEV_DL_LINK_ON);
	} else if (disconnected) {
		interface_link_event(ifp, KEV_DL_LINK_OFF);
		interface_link_event(peer, KEV_DL_LINK_OFF);
	}
	return error;
}

static int
feth_set_media(ifnet_t ifp, struct if_fake_request * iffr)
{
	if_fake_ref     fakeif;
	int             error;

	if (iffr->iffr_media.iffm_count > IF_FAKE_MEDIA_LIST_MAX) {
		/* list is too long */
		return EINVAL;
	}
	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif == NULL) {
		error = EINVAL;
		goto done;
	}
	fakeif->iff_media_count = iffr->iffr_media.iffm_count;
	bcopy(iffr->iffr_media.iffm_list, fakeif->iff_media_list,
	    iffr->iffr_media.iffm_count * sizeof(fakeif->iff_media_list[0]));
#if 0
	/* XXX: "auto-negotiate" active with peer? */
	/* generate link status event? */
	fakeif->iff_media_current = iffr->iffr_media.iffm_current;
#endif
	error = 0;
done:
	feth_unlock();
	return error;
}

static int
if_fake_request_copyin(user_addr_t user_addr,
    struct if_fake_request *iffr, u_int32_t len)
{
	int     error;

	if (user_addr == USER_ADDR_NULL || len < sizeof(*iffr)) {
		error = EINVAL;
		goto done;
	}
	error = copyin(user_addr, iffr, sizeof(*iffr));
	if (error != 0) {
		goto done;
	}
	if (iffr->iffr_reserved[0] != 0 || iffr->iffr_reserved[1] != 0 ||
	    iffr->iffr_reserved[2] != 0 || iffr->iffr_reserved[3] != 0) {
		error = EINVAL;
		goto done;
	}
done:
	return error;
}

static int
feth_set_drvspec(ifnet_t ifp, uint32_t cmd, u_int32_t len,
    user_addr_t user_addr)
{
	int                     error;
	struct if_fake_request  iffr;
	ifnet_t                 peer;

	switch (cmd) {
	case IF_FAKE_S_CMD_SET_PEER:
		error = if_fake_request_copyin(user_addr, &iffr, len);
		if (error != 0) {
			break;
		}
		if (iffr.iffr_peer_name[0] == '\0') {
			error = feth_config(ifp, NULL);
			break;
		}

		/* ensure nul termination */
		iffr.iffr_peer_name[IFNAMSIZ - 1] = '\0';
		peer = ifunit(iffr.iffr_peer_name);
		if (peer == NULL) {
			error = ENXIO;
			break;
		}
		if (ifnet_type(peer) != IFT_ETHER) {
			error = EINVAL;
			break;
		}
		if (strcmp(ifnet_name(peer), FAKE_ETHER_NAME) != 0) {
			error = EINVAL;
			break;
		}
		error = feth_config(ifp, peer);
		break;
	case IF_FAKE_S_CMD_SET_MEDIA:
		error = if_fake_request_copyin(user_addr, &iffr, len);
		if (error != 0) {
			break;
		}
		error = feth_set_media(ifp, &iffr);
		break;
	case IF_FAKE_S_CMD_SET_DEQUEUE_STALL:
		error = if_fake_request_copyin(user_addr, &iffr, len);
		if (error != 0) {
			break;
		}
		error = feth_enable_dequeue_stall(ifp,
		    iffr.iffr_dequeue_stall);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return error;
}

static int
feth_get_drvspec(ifnet_t ifp, u_int32_t cmd, u_int32_t len,
    user_addr_t user_addr)
{
	int                     error = EOPNOTSUPP;
	if_fake_ref             fakeif;
	struct if_fake_request  iffr;
	ifnet_t                 peer;

	switch (cmd) {
	case IF_FAKE_G_CMD_GET_PEER:
		if (len < sizeof(iffr)) {
			error = EINVAL;
			break;
		}
		feth_lock();
		fakeif = ifnet_get_if_fake(ifp);
		if (fakeif == NULL) {
			feth_unlock();
			error = EOPNOTSUPP;
			break;
		}
		peer = fakeif->iff_peer;
		feth_unlock();
		bzero(&iffr, sizeof(iffr));
		if (peer != NULL) {
			strlcpy(iffr.iffr_peer_name,
			    if_name(peer),
			    sizeof(iffr.iffr_peer_name));
		}
		error = copyout(&iffr, user_addr, sizeof(iffr));
		break;
	default:
		break;
	}
	return error;
}

union ifdrvu {
	struct ifdrv32  *ifdrvu_32;
	struct ifdrv64  *ifdrvu_64;
	void            *ifdrvu_p;
};

static int
feth_ioctl(ifnet_t ifp, u_long cmd, void * data)
{
	unsigned int            count;
	struct ifdevmtu *       devmtu_p;
	union ifdrvu            drv;
	uint32_t                drv_cmd;
	uint32_t                drv_len;
	boolean_t               drv_set_command = FALSE;
	int                     error = 0;
	struct ifmediareq *     ifmr;
	struct ifreq *          ifr;
	if_fake_ref             fakeif;
	int                     status;
	user_addr_t             user_addr;

	ifr = (struct ifreq *)data;
	switch (cmd) {
	case SIOCSIFADDR:
		ifnet_set_flags(ifp, IFF_UP, IFF_UP);
		break;

	case SIOCGIFMEDIA32:
	case SIOCGIFMEDIA64:
		feth_lock();
		fakeif = ifnet_get_if_fake(ifp);
		if (fakeif == NULL) {
			feth_unlock();
			return EOPNOTSUPP;
		}
		status = (fakeif->iff_peer != NULL)
		    ? (IFM_AVALID | IFM_ACTIVE) : IFM_AVALID;
		ifmr = (struct ifmediareq *)data;
		user_addr = (cmd == SIOCGIFMEDIA64) ?
		    ((struct ifmediareq64 *)ifmr)->ifmu_ulist :
		    CAST_USER_ADDR_T(((struct ifmediareq32 *)ifmr)->ifmu_ulist);
		count = ifmr->ifm_count;
		ifmr->ifm_active = IFM_ETHER;
		ifmr->ifm_current = IFM_ETHER;
		ifmr->ifm_mask = 0;
		ifmr->ifm_status = status;
		if (user_addr == USER_ADDR_NULL) {
			ifmr->ifm_count = fakeif->iff_media_count;
		} else if (count > 0) {
			if (count > fakeif->iff_media_count) {
				count = fakeif->iff_media_count;
			}
			ifmr->ifm_count = count;
			error = copyout(&fakeif->iff_media_list, user_addr,
			    count * sizeof(int));
		}
		feth_unlock();
		break;

	case SIOCGIFDEVMTU:
		devmtu_p = &ifr->ifr_devmtu;
		devmtu_p->ifdm_current = ifnet_mtu(ifp);
		devmtu_p->ifdm_max = feth_max_mtu(ifp);
		devmtu_p->ifdm_min = IF_MINMTU;
		break;

	case SIOCSIFMTU:
		if ((unsigned int)ifr->ifr_mtu > feth_max_mtu(ifp) ||
		    ifr->ifr_mtu < IF_MINMTU) {
			error = EINVAL;
		} else {
			error = ifnet_set_mtu(ifp, ifr->ifr_mtu);
		}
		break;

	case SIOCSDRVSPEC32:
	case SIOCSDRVSPEC64:
		error = proc_suser(current_proc());
		if (error != 0) {
			break;
		}
		drv_set_command = TRUE;
	/* FALL THROUGH */
	case SIOCGDRVSPEC32:
	case SIOCGDRVSPEC64:
		drv.ifdrvu_p = data;
		if (cmd == SIOCGDRVSPEC32 || cmd == SIOCSDRVSPEC32) {
			drv_cmd = drv.ifdrvu_32->ifd_cmd;
			drv_len = drv.ifdrvu_32->ifd_len;
			user_addr = CAST_USER_ADDR_T(drv.ifdrvu_32->ifd_data);
		} else {
			drv_cmd = drv.ifdrvu_64->ifd_cmd;
			drv_len = drv.ifdrvu_64->ifd_len;
			user_addr = drv.ifdrvu_64->ifd_data;
		}
		if (drv_set_command) {
			error = feth_set_drvspec(ifp, drv_cmd, drv_len,
			    user_addr);
		} else {
			error = feth_get_drvspec(ifp, drv_cmd, drv_len,
			    user_addr);
		}
		break;

	case SIOCSIFLLADDR:
		error = ifnet_set_lladdr(ifp, ifr->ifr_addr.sa_data,
		    ifr->ifr_addr.sa_len);
		break;

	case SIOCSIFFLAGS:
		if ((ifp->if_flags & IFF_UP) != 0) {
			/* marked up, set running if not already set */
			if ((ifp->if_flags & IFF_RUNNING) == 0) {
				/* set running */
				error = ifnet_set_flags(ifp, IFF_RUNNING,
				    IFF_RUNNING);
			}
		} else if ((ifp->if_flags & IFF_RUNNING) != 0) {
			/* marked down, clear running */
			error = ifnet_set_flags(ifp, 0, IFF_RUNNING);
		}
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = 0;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return error;
}

static void
feth_if_free(ifnet_t ifp)
{
	if_fake_ref             fakeif;

	if (ifp == NULL) {
		return;
	}
	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif == NULL) {
		feth_unlock();
		return;
	}
	ifp->if_softc = NULL;
	feth_unlock();
	feth_release(fakeif);
	ifnet_release(ifp);
	return;
}

__private_extern__ void
if_fake_init(void)
{
	int error;

	feth_lock_init();
	error = if_clone_attach(&feth_cloner);
	if (error != 0) {
		return;
	}
	return;
}
