/*
 * Copyright (c) 2004-2014 Apple Inc. All rights reserved.
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
 * if_bond.c 
 * - bond/failover interface
 * - implements IEEE 802.3ad Link Aggregation
 */

/*
 * Modification History:
 *
 * April 29, 2004	Dieter Siegmund (dieter@apple.com)
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

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/kpi_interface.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_types.h>
#include <net/if_bond_var.h>
#include <net/ieee8023ad.h>
#include <net/lacp.h>
#include <net/dlil.h>
#include <sys/time.h>
#include <net/devtimer.h>
#include <net/if_vlan_var.h>
#include <net/kpi_protocol.h>

#include <kern/locks.h>
#include <libkern/OSAtomic.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <net/if_media.h>
#include <net/multicast_list.h>

static struct ether_addr slow_proto_multicast = {
    IEEE8023AD_SLOW_PROTO_MULTICAST
};

#define	BOND_MAXUNIT		128
#define BONDNAME		"bond"
#define M_BOND	 		M_DEVBUF

#define EA_FORMAT	"%x:%x:%x:%x:%x:%x"
#define EA_CH(e, i)	((u_char)((u_char *)(e))[(i)])
#define EA_LIST(ea)	EA_CH(ea,0),EA_CH(ea,1),EA_CH(ea,2),EA_CH(ea,3),EA_CH(ea,4),EA_CH(ea,5)

#define timestamp_printf	printf

/**
 ** bond locks
 **/
static __inline__ lck_grp_t *
my_lck_grp_alloc_init(const char * grp_name)
{
    lck_grp_t *		grp;
    lck_grp_attr_t *	grp_attrs;
    
    grp_attrs = lck_grp_attr_alloc_init();
    grp = lck_grp_alloc_init(grp_name, grp_attrs);
    lck_grp_attr_free(grp_attrs);
    return (grp);
}

static __inline__ lck_mtx_t *
my_lck_mtx_alloc_init(lck_grp_t * lck_grp)
{
    lck_attr_t * 	lck_attrs;
    lck_mtx_t *		lck_mtx;

    lck_attrs = lck_attr_alloc_init();
    lck_mtx = lck_mtx_alloc_init(lck_grp, lck_attrs);
    lck_attr_free(lck_attrs);
    return (lck_mtx);
}

static lck_mtx_t * 	bond_lck_mtx;

static __inline__ void
bond_lock_init(void)
{
    lck_grp_t *		bond_lck_grp;

    bond_lck_grp = my_lck_grp_alloc_init("if_bond");
    bond_lck_mtx = my_lck_mtx_alloc_init(bond_lck_grp);
}

static __inline__ void
bond_assert_lock_held(void)
{
    LCK_MTX_ASSERT(bond_lck_mtx, LCK_MTX_ASSERT_OWNED);
    return;
}

static __inline__ void
bond_assert_lock_not_held(void)
{
    LCK_MTX_ASSERT(bond_lck_mtx, LCK_MTX_ASSERT_NOTOWNED);
    return;
}

static __inline__ void
bond_lock(void)
{
    lck_mtx_lock(bond_lck_mtx);
    return;
}

static __inline__ void
bond_unlock(void)
{
    lck_mtx_unlock(bond_lck_mtx);
    return;
}

/**
 ** bond structures, types
 **/

struct LAG_info_s {
    lacp_system			li_system;
    lacp_system_priority	li_system_priority;
    lacp_key			li_key;
};
typedef struct LAG_info_s LAG_info, * LAG_info_ref;

struct bondport_s;
TAILQ_HEAD(port_list, bondport_s);
struct ifbond_s;
TAILQ_HEAD(ifbond_list, ifbond_s);
struct LAG_s;
TAILQ_HEAD(lag_list, LAG_s);

typedef struct ifbond_s ifbond, * ifbond_ref;
typedef struct bondport_s bondport, * bondport_ref;

struct LAG_s {
    TAILQ_ENTRY(LAG_s)		lag_list;
    struct port_list		lag_port_list;
    short			lag_port_count;
    short			lag_selected_port_count;
    int				lag_active_media;
    LAG_info			lag_info;
};
typedef struct LAG_s LAG, * LAG_ref;

typedef struct partner_state_s {
    LAG_info			ps_lag_info;
    lacp_port			ps_port;
    lacp_port_priority		ps_port_priority;
    lacp_actor_partner_state	ps_state;
} partner_state, * partner_state_ref;

struct ifbond_s {
    TAILQ_ENTRY(ifbond_s) 	ifb_bond_list;
    int				ifb_flags;
    SInt32			ifb_retain_count;
    char 			ifb_name[IFNAMSIZ];
    struct ifnet *		ifb_ifp;
    bpf_packet_func		ifb_bpf_input;
    bpf_packet_func 		ifb_bpf_output;
    int				ifb_altmtu;
    struct port_list		ifb_port_list;
    short			ifb_port_count;
    struct lag_list		ifb_lag_list;
    lacp_key			ifb_key;
    short			ifb_max_active; /* 0 == unlimited */
    LAG_ref			ifb_active_lag;
    struct ifmultiaddr *	ifb_ifma_slow_proto;
    bondport_ref *		ifb_distributing_array;
    int				ifb_distributing_count;
    int				ifb_last_link_event;
    int				ifb_mode; /* LACP, STATIC */
};

struct media_info {
    int		mi_active;
    int		mi_status;
};

enum {
    ReceiveState_none = 0,
    ReceiveState_INITIALIZE = 1,
    ReceiveState_PORT_DISABLED = 2,
    ReceiveState_EXPIRED = 3,
    ReceiveState_LACP_DISABLED = 4,
    ReceiveState_DEFAULTED = 5,
    ReceiveState_CURRENT = 6,
};

typedef u_char ReceiveState;

enum {
    SelectedState_UNSELECTED = IF_BOND_STATUS_SELECTED_STATE_UNSELECTED,
    SelectedState_SELECTED = IF_BOND_STATUS_SELECTED_STATE_SELECTED,
    SelectedState_STANDBY = IF_BOND_STATUS_SELECTED_STATE_STANDBY
};
typedef u_char SelectedState;

static __inline__ const char *
SelectedStateString(SelectedState s)
{
    static const char * names[] = { "UNSELECTED", "SELECTED", "STANDBY" };

    if (s <= SelectedState_STANDBY) {
	return (names[s]);
    }
    return ("<unknown>");
}

enum {
    MuxState_none = 0,
    MuxState_DETACHED = 1,
    MuxState_WAITING = 2,
    MuxState_ATTACHED = 3,
    MuxState_COLLECTING_DISTRIBUTING = 4,
};

typedef u_char MuxState;

struct bondport_s {
    TAILQ_ENTRY(bondport_s) 	po_port_list;
    ifbond_ref			po_bond;
    struct multicast_list 	po_multicast;
    struct ifnet *		po_ifp;
    struct ether_addr		po_saved_addr;
    int				po_enabled;
    char			po_name[IFNAMSIZ];
    struct ifdevmtu		po_devmtu;

    /* LACP */
    TAILQ_ENTRY(bondport_s) 	po_lag_port_list;
    devtimer_ref		po_current_while_timer;
    devtimer_ref		po_periodic_timer;
    devtimer_ref		po_wait_while_timer;
    devtimer_ref		po_transmit_timer;
    partner_state		po_partner_state;
    lacp_port_priority		po_priority;
    lacp_actor_partner_state	po_actor_state;
    u_char			po_flags;
    u_char			po_periodic_interval;
    u_char			po_n_transmit;
    ReceiveState		po_receive_state;
    MuxState			po_mux_state;
    SelectedState		po_selected;
    int32_t			po_last_transmit_secs;
    struct media_info		po_media_info;
    LAG_ref			po_lag;
};

#define	IFBF_PROMISC		0x1	/* promiscuous mode */
#define IFBF_IF_DETACHING	0x2	/* interface is detaching */
#define IFBF_LLADDR		0x4	/* specific link address requested */
#define IFBF_CHANGE_IN_PROGRESS	0x8	/* interface add/remove in progress */

static int bond_get_status(ifbond_ref ifb, struct if_bond_req * ibr_p, 
			   user_addr_t datap);

static __inline__ int
ifbond_flags_if_detaching(ifbond_ref ifb)
{
    return ((ifb->ifb_flags & IFBF_IF_DETACHING) != 0);
}

static __inline__ void
ifbond_flags_set_if_detaching(ifbond_ref ifb)
{
    ifb->ifb_flags |= IFBF_IF_DETACHING;
    return;
}

static __inline__ int
ifbond_flags_lladdr(ifbond_ref ifb)
{
    return ((ifb->ifb_flags & IFBF_LLADDR) != 0);
}

static __inline__ int
ifbond_flags_change_in_progress(ifbond_ref ifb)
{
    return ((ifb->ifb_flags & IFBF_CHANGE_IN_PROGRESS) != 0);
}

static __inline__ void
ifbond_flags_set_change_in_progress(ifbond_ref ifb)
{
    ifb->ifb_flags |= IFBF_CHANGE_IN_PROGRESS;
    return;
}

static __inline__ void
ifbond_flags_clear_change_in_progress(ifbond_ref ifb)
{
    ifb->ifb_flags &= ~IFBF_CHANGE_IN_PROGRESS;
    return;
}

/*
 * bondport_ref->po_flags bits
 */
#define BONDPORT_FLAGS_NTT		0x01
#define BONDPORT_FLAGS_READY		0x02
#define BONDPORT_FLAGS_SELECTED_CHANGED	0x04
#define BONDPORT_FLAGS_MUX_ATTACHED	0x08
#define BONDPORT_FLAGS_DISTRIBUTING	0x10
#define BONDPORT_FLAGS_UNUSED2		0x20
#define BONDPORT_FLAGS_UNUSED3		0x40
#define BONDPORT_FLAGS_UNUSED4		0x80

static __inline__ void
bondport_flags_set_ntt(bondport_ref p)
{
    p->po_flags |= BONDPORT_FLAGS_NTT;
    return;
}

static __inline__ void
bondport_flags_clear_ntt(bondport_ref p)
{
    p->po_flags &= ~BONDPORT_FLAGS_NTT;
    return;
}

static __inline__ int
bondport_flags_ntt(bondport_ref p)
{
    return ((p->po_flags & BONDPORT_FLAGS_NTT) != 0);
}

static __inline__ void
bondport_flags_set_ready(bondport_ref p)
{
    p->po_flags |= BONDPORT_FLAGS_READY;
    return;
}

static __inline__ void
bondport_flags_clear_ready(bondport_ref p)
{
    p->po_flags &= ~BONDPORT_FLAGS_READY;
    return;
}

static __inline__ int
bondport_flags_ready(bondport_ref p)
{
    return ((p->po_flags & BONDPORT_FLAGS_READY) != 0);
}

static __inline__ void
bondport_flags_set_selected_changed(bondport_ref p)
{
    p->po_flags |= BONDPORT_FLAGS_SELECTED_CHANGED;
    return;
}

static __inline__ void
bondport_flags_clear_selected_changed(bondport_ref p)
{
    p->po_flags &= ~BONDPORT_FLAGS_SELECTED_CHANGED;
    return;
}

static __inline__ int
bondport_flags_selected_changed(bondport_ref p)
{
    return ((p->po_flags & BONDPORT_FLAGS_SELECTED_CHANGED) != 0);
}

static __inline__ void
bondport_flags_set_mux_attached(bondport_ref p)
{
    p->po_flags |= BONDPORT_FLAGS_MUX_ATTACHED;
    return;
}

static __inline__ void
bondport_flags_clear_mux_attached(bondport_ref p)
{
    p->po_flags &= ~BONDPORT_FLAGS_MUX_ATTACHED;
    return;
}

static __inline__ int
bondport_flags_mux_attached(bondport_ref p)
{
    return ((p->po_flags & BONDPORT_FLAGS_MUX_ATTACHED) != 0);
}

static __inline__ void
bondport_flags_set_distributing(bondport_ref p)
{
    p->po_flags |= BONDPORT_FLAGS_DISTRIBUTING;
    return;
}

static __inline__ void
bondport_flags_clear_distributing(bondport_ref p)
{
    p->po_flags &= ~BONDPORT_FLAGS_DISTRIBUTING;
    return;
}

static __inline__ int
bondport_flags_distributing(bondport_ref p)
{
    return ((p->po_flags & BONDPORT_FLAGS_DISTRIBUTING) != 0);
}

typedef struct bond_globals_s {
    struct ifbond_list		ifbond_list;
    lacp_system			system;
    lacp_system_priority	system_priority;
    int				verbose;
} * bond_globals_ref;

static bond_globals_ref	g_bond;

/**
 ** packet_buffer routines
 ** - thin wrapper for mbuf
 **/

typedef struct mbuf * packet_buffer_ref;

static packet_buffer_ref
packet_buffer_allocate(int length)
{
    packet_buffer_ref	m;
    int			size;

    /* leave room for ethernet header */
    size = length + sizeof(struct ether_header);
    if (size > (int)MHLEN) {
	if (size > (int)MCLBYTES) {
	    printf("bond: packet_buffer_allocate size %d > max %u\n",
	           size, MCLBYTES);
	    return (NULL);
	}
	m = m_getcl(M_WAITOK, MT_DATA, M_PKTHDR);
    } else {
	m = m_gethdr(M_WAITOK, MT_DATA);
    }
    if (m == NULL) {
	return (NULL);
    }
    m->m_len = size;
    m->m_pkthdr.len = size;
    return (m);
}

static void *
packet_buffer_byteptr(packet_buffer_ref buf)
{
    return (buf->m_data + sizeof(struct ether_header));
}

typedef enum {
    LAEventStart,
    LAEventTimeout,
    LAEventPacket,
    LAEventMediaChange,
    LAEventSelectedChange,
    LAEventPortMoved,
    LAEventReady
} LAEvent;

/**
 ** Receive machine
 **/
static void
bondport_receive_machine(bondport_ref p, LAEvent event,
			 void * event_data);
/**
 ** Periodic Transmission machine
 **/
static void
bondport_periodic_transmit_machine(bondport_ref p, LAEvent event,
				   void * event_data);

/**
 ** Transmit machine
 **/
#define TRANSMIT_MACHINE_TX_IMMEDIATE	((void *)1)

static void
bondport_transmit_machine(bondport_ref p, LAEvent event,
			  void * event_data);

/**
 ** Mux machine
 **/
static void
bondport_mux_machine(bondport_ref p, LAEvent event,
		     void * event_data);

/**
 ** bond, LAG
 **/
static void
ifbond_activate_LAG(ifbond_ref bond, LAG_ref lag, int active_media);

static void
ifbond_deactivate_LAG(ifbond_ref bond, LAG_ref lag);

static int
ifbond_all_ports_ready(ifbond_ref bond);

static LAG_ref
ifbond_find_best_LAG(ifbond_ref bond, int * active_media);

static int
LAG_get_aggregatable_port_count(LAG_ref lag, int * active_media);

static int
ifbond_selection(ifbond_ref bond);


/**
 ** bondport
 **/

static void
bondport_receive_lacpdu(bondport_ref p, lacpdu_ref in_lacpdu_p);

static void
bondport_slow_proto_transmit(bondport_ref p, packet_buffer_ref buf);

static bondport_ref
bondport_create(struct ifnet * port_ifp, lacp_port_priority priority,
		int active, int short_timeout, int * error);
static void
bondport_start(bondport_ref p);

static void
bondport_free(bondport_ref p);

static int
bondport_aggregatable(bondport_ref p);

static int
bondport_remove_from_LAG(bondport_ref p);

static void 
bondport_set_selected(bondport_ref p, SelectedState s);

static int
bondport_matches_LAG(bondport_ref p, LAG_ref lag);

static void
bondport_link_status_changed(bondport_ref p);

static void
bondport_enable_distributing(bondport_ref p);

static void
bondport_disable_distributing(bondport_ref p);

static __inline__ int
bondport_collecting(bondport_ref p)
{
    if (p->po_bond->ifb_mode == IF_BOND_MODE_LACP) {
	return (lacp_actor_partner_state_collecting(p->po_actor_state));
    }
    return (TRUE);
}

/**
 ** bond interface/dlil specific routines
 **/
static int bond_clone_create(struct if_clone *, u_int32_t, void *);
static int bond_clone_destroy(struct ifnet *);
static int bond_input(ifnet_t ifp, protocol_family_t protocol, mbuf_t m,
					  char *frame_header);
static int bond_output(struct ifnet *ifp, struct mbuf *m);
static int bond_ioctl(struct ifnet *ifp, u_long cmd, void * addr);
static int bond_set_bpf_tap(struct ifnet * ifp, bpf_tap_mode mode,
			    bpf_packet_func func);
static int bond_attach_protocol(struct ifnet *ifp);
static int bond_detach_protocol(struct ifnet *ifp);
static int bond_setmulti(struct ifnet *ifp);
static int bond_add_interface(struct ifnet * ifp, struct ifnet * port_ifp);
static int bond_remove_interface(ifbond_ref ifb, struct ifnet * port_ifp);
static void bond_if_free(struct ifnet * ifp);

static struct if_clone bond_cloner = IF_CLONE_INITIALIZER(BONDNAME,
							  bond_clone_create, 
							  bond_clone_destroy, 
							  0,
							  BOND_MAXUNIT);
static	void interface_link_event(struct ifnet * ifp, u_int32_t event_code);

static int
siocsifmtu(struct ifnet * ifp, int mtu)
{
    struct ifreq	ifr;

    bzero(&ifr, sizeof(ifr));
    ifr.ifr_mtu = mtu;
    return (ifnet_ioctl(ifp, 0, SIOCSIFMTU, &ifr));
}

static int
siocgifdevmtu(struct ifnet * ifp, struct ifdevmtu * ifdm_p)
{
    struct ifreq	ifr;
    int 		error;

    bzero(&ifr, sizeof(ifr));
    error = ifnet_ioctl(ifp, 0, SIOCGIFDEVMTU, &ifr);
    if (error == 0) {
	*ifdm_p = ifr.ifr_devmtu;
    }
    return (error);
}

static __inline__ void
ether_addr_copy(void * dest, const void * source)
{
    bcopy(source, dest, ETHER_ADDR_LEN);
    return;
}

static __inline__ void
ifbond_retain(ifbond_ref ifb)
{
    OSIncrementAtomic(&ifb->ifb_retain_count);
}

static __inline__ void
ifbond_release(ifbond_ref ifb)
{
    UInt32		old_retain_count;

    old_retain_count = OSDecrementAtomic(&ifb->ifb_retain_count);
    switch (old_retain_count) {
    case 0:
	panic("ifbond_release: retain count is 0\n");
	break;
    case 1:
	if (g_bond->verbose) {
	    printf("ifbond_release(%s)\n", ifb->ifb_name);
	}
	if (ifb->ifb_ifma_slow_proto != NULL) {
	    if (g_bond->verbose) {
		printf("ifbond_release(%s) removing multicast\n",
		       ifb->ifb_name);
	    }
	    (void) if_delmulti_anon(ifb->ifb_ifma_slow_proto->ifma_ifp,
	        ifb->ifb_ifma_slow_proto->ifma_addr);
	    IFMA_REMREF(ifb->ifb_ifma_slow_proto);
	}
	if (ifb->ifb_distributing_array != NULL) {
	    FREE(ifb->ifb_distributing_array, M_BOND);
	}
	FREE(ifb, M_BOND);
	break;
    default:
	break;
    }
    return;
}

/*
 * Function: ifbond_wait
 * Purpose:
 *   Allows a single thread to gain exclusive access to the ifbond
 *   data structure.  Some operations take a long time to complete, 
 *   and some have side-effects that we can't predict.  Holding the
 *   bond_lock() across such operations is not possible.
 *
 *   For example:
 *   1) The SIOCSIFLLADDR ioctl takes a long time (several seconds) to 
 *      complete.  Simply holding the bond_lock() would freeze all other
 *      data structure accesses during that time.
 *   2) When we attach our protocol to the interface, a dlil event is
 *      generated and invokes our bond_event() function.  bond_event()
 *      needs to take the bond_lock(), but we're already holding it, so
 *      we're deadlocked against ourselves.
 * Notes:
 *   Before calling, you must be holding the bond_lock and have taken
 *   a reference on the ifbond_ref.
 */
static void
ifbond_wait(ifbond_ref ifb, const char * msg)
{
    int		waited = 0;

    /* other add/remove in progress */
    while (ifbond_flags_change_in_progress(ifb)) {
	if (g_bond->verbose) {
	    printf("%s: %s msleep\n", ifb->ifb_name, msg);
	}
	waited = 1;
	(void)msleep(ifb, bond_lck_mtx, PZERO, msg, 0);
    }
    /* prevent other bond list remove/add from taking place */
    ifbond_flags_set_change_in_progress(ifb);
    if (g_bond->verbose && waited) {
	printf("%s: %s woke up\n", ifb->ifb_name, msg);
    }
    return;
}

/*
 * Function: ifbond_signal
 * Purpose:
 *   Allows the thread that previously invoked ifbond_wait() to 
 *   give up exclusive access to the ifbond data structure, and wake up
 *   any other threads waiting to access
 * Notes:
 *   Before calling, you must be holding the bond_lock and have taken
 *   a reference on the ifbond_ref.
 */
static void
ifbond_signal(ifbond_ref ifb, const char * msg)
{
    ifbond_flags_clear_change_in_progress(ifb);
    wakeup((caddr_t)ifb);
    if (g_bond->verbose) {
	printf("%s: %s wakeup\n", ifb->ifb_name, msg);
    }
    return;
}

/**
 ** Media information
 **/

static int
link_speed(int active)
{
    switch (IFM_SUBTYPE(active)) {
    case IFM_10_T:
    case IFM_10_2:
    case IFM_10_5:
    case IFM_10_STP:
    case IFM_10_FL:
	return (10);
    case IFM_100_TX:
    case IFM_100_FX:
    case IFM_100_T4:
    case IFM_100_VG:
    case IFM_100_T2:
	return (100);
    case IFM_1000_SX:
    case IFM_1000_LX:
    case IFM_1000_CX:
    case IFM_1000_TX:
	return (1000);
    case IFM_HPNA_1:
	return (0);
    default:
	/* assume that new defined types are going to be at least 10GigE */
    case IFM_10G_SR:
    case IFM_10G_LR:
	return (10000);
    case IFM_2500_T:
	return (2500);
    case IFM_5000_T:
	return (5000);
    }
}

static __inline__ int
media_active(const struct media_info * mi)
{
    if ((mi->mi_status & IFM_AVALID) == 0) {
	return (1);
    }
    return ((mi->mi_status & IFM_ACTIVE) != 0);
}

static __inline__ int
media_full_duplex(const struct media_info * mi)
{
    return ((mi->mi_active & IFM_FDX) != 0);
}

static __inline__ int
media_speed(const struct media_info * mi)
{
    return (link_speed(mi->mi_active));
}

static struct media_info
interface_media_info(struct ifnet * ifp)
{
    struct ifmediareq	ifmr;
    struct media_info	mi;

    bzero(&mi, sizeof(mi));
    bzero(&ifmr, sizeof(ifmr));
    if (ifnet_ioctl(ifp, 0, SIOCGIFMEDIA, &ifmr) == 0) {
	if (ifmr.ifm_count != 0) {
	    mi.mi_status = ifmr.ifm_status;
	    mi.mi_active = ifmr.ifm_active;
	}
    }
    return (mi);
}

static int
if_siflladdr(struct ifnet * ifp, const struct ether_addr * ea_p)
{
    struct ifreq	ifr;

    /*
     * XXX setting the sa_len to ETHER_ADDR_LEN is wrong, but the driver
     * currently expects it that way
     */
    ifr.ifr_addr.sa_family = AF_UNSPEC;
    ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
    ether_addr_copy(ifr.ifr_addr.sa_data, ea_p);
    return (ifnet_ioctl(ifp, 0, SIOCSIFLLADDR, &ifr));
}

/**
 ** bond_globals
 **/
static bond_globals_ref
bond_globals_create(lacp_system_priority sys_pri,
		    lacp_system_ref sys)
{
    bond_globals_ref	b;

    b = _MALLOC(sizeof(*b), M_BOND, M_WAITOK | M_ZERO);
    if (b == NULL) {
	return (NULL);
    }
    TAILQ_INIT(&b->ifbond_list);
    b->system = *sys;
    b->system_priority = sys_pri;
    return (b);
}

static int
bond_globals_init(void)
{
    bond_globals_ref	b;
    int			i;
    struct ifnet * 	ifp;

    bond_assert_lock_not_held();

    if (g_bond != NULL) {
	return (0);
    }

    /*
     * use en0's ethernet address as the system identifier, and if it's not
     * there, use en1 .. en3
     */
    ifp = NULL;
    for (i = 0; i < 4; i++) {
	char 		ifname[IFNAMSIZ+1];
	snprintf(ifname, sizeof(ifname), "en%d", i);
	ifp = ifunit(ifname);
	if (ifp != NULL) {
	    break;
	}
    }
    b = NULL;
    if (ifp != NULL) {
	b = bond_globals_create(0x8000, (lacp_system_ref)IF_LLADDR(ifp));
    }
    bond_lock();
    if (g_bond != NULL) {
	bond_unlock();
	_FREE(b, M_BOND);
	return (0);
    }
    g_bond = b;
    bond_unlock();
    if (ifp == NULL) {
	return (ENXIO);
    }
    if (b == NULL) {
	return (ENOMEM);
    }
    return (0);
}

static void
bond_bpf_vlan(struct ifnet * ifp, struct mbuf * m,
	      const struct ether_header * eh_p,
	      u_int16_t vlan_tag, bpf_packet_func func)
{
    struct ether_vlan_header *	vlh_p;
    struct mbuf *		vl_m;

    vl_m = m_get(M_DONTWAIT, MT_DATA);
    if (vl_m == NULL) {
	return;
    }
    /* populate a new mbuf containing the vlan ethernet header */
    vl_m->m_len = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
    vlh_p = mtod(vl_m, struct ether_vlan_header *);
    bcopy(eh_p, vlh_p, offsetof(struct ether_header, ether_type));
    vlh_p->evl_encap_proto = htons(ETHERTYPE_VLAN);
    vlh_p->evl_tag = htons(vlan_tag);
    vlh_p->evl_proto = eh_p->ether_type;
    vl_m->m_next = m;
    (*func)(ifp, vl_m);
    vl_m->m_next = NULL;
    m_free(vl_m);
    return;
}

static __inline__ void 
bond_bpf_output(struct ifnet * ifp, struct mbuf * m, 
		bpf_packet_func func)
{
    if (func != NULL) {
	if (m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) {
	    const struct ether_header * eh_p;
	    eh_p = mtod(m, const struct ether_header *);
	    m->m_data += ETHER_HDR_LEN;
	    m->m_len -= ETHER_HDR_LEN;
	    bond_bpf_vlan(ifp, m, eh_p, m->m_pkthdr.vlan_tag, func);
	    m->m_data -= ETHER_HDR_LEN;
	    m->m_len += ETHER_HDR_LEN;
	} else {
	    (*func)(ifp, m);
	}
    }
    return;
}

static __inline__ void 
bond_bpf_input(ifnet_t ifp, mbuf_t m, const struct ether_header * eh_p,
		bpf_packet_func func)
{
    if (func != NULL) {
	if (m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) {
	    bond_bpf_vlan(ifp, m, eh_p, m->m_pkthdr.vlan_tag, func);
	} else {
	    /* restore the header */
	    m->m_data -= ETHER_HDR_LEN;
	    m->m_len += ETHER_HDR_LEN;
	    (*func)(ifp, m);
	    m->m_data += ETHER_HDR_LEN;
	    m->m_len -= ETHER_HDR_LEN;
	}
    }
    return;
}

/*
 * Function: bond_setmulti
 * Purpose:
 *   Enable multicast reception on "our" interface by enabling multicasts on
 *   each of the member ports.
 */
static int
bond_setmulti(struct ifnet * ifp)
{
    ifbond_ref		ifb;
    int			error;
    int			result = 0;
    bondport_ref	p;

    bond_lock();
    ifb = ifnet_softc(ifp);
    if (ifb == NULL || ifbond_flags_if_detaching(ifb) 
	|| TAILQ_EMPTY(&ifb->ifb_port_list)) {
	bond_unlock();
	return (0);
    }
    ifbond_retain(ifb);
    ifbond_wait(ifb, "bond_setmulti");

    if (ifbond_flags_if_detaching(ifb)) {
	/* someone destroyed the bond while we were waiting */
	result = EBUSY;
	goto signal_done;
    }
    bond_unlock();

    /* ifbond_wait() let's us safely walk the list without holding the lock */
    TAILQ_FOREACH(p, &ifb->ifb_port_list, po_port_list) {
	struct ifnet *	port_ifp = p->po_ifp;

	error = multicast_list_program(&p->po_multicast,
				       ifp, port_ifp);
	if (error != 0) {
	    printf("bond_setmulti(%s): "
		   "multicast_list_program(%s%d) failed, %d\n",
		   ifb->ifb_name, ifnet_name(port_ifp),
		   ifnet_unit(port_ifp), error);
	    result = error;
	}
    }
    bond_lock();
 signal_done:
    ifbond_signal(ifb, "bond_setmulti");
    bond_unlock();
    ifbond_release(ifb);
    return (result);
}

static int
bond_clone_attach(void)
{
    int error;

    if ((error = if_clone_attach(&bond_cloner)) != 0)
	return error;
    bond_lock_init();
    return 0;
}

static int
ifbond_add_slow_proto_multicast(ifbond_ref ifb)
{
    int				error;
    struct ifmultiaddr * 	ifma = NULL;
    struct sockaddr_dl		sdl;

    bond_assert_lock_not_held();

    bzero(&sdl, sizeof(sdl));
    sdl.sdl_len = sizeof(sdl);
    sdl.sdl_family = AF_LINK;
    sdl.sdl_type = IFT_ETHER;
    sdl.sdl_nlen = 0;
    sdl.sdl_alen = sizeof(slow_proto_multicast);
    bcopy(&slow_proto_multicast, sdl.sdl_data, sizeof(slow_proto_multicast));
    error = if_addmulti_anon(ifb->ifb_ifp, (struct sockaddr *)&sdl, &ifma);
    if (error == 0) {
	ifb->ifb_ifma_slow_proto = ifma;
    }
    return (error);
}

static int
bond_clone_create(struct if_clone * ifc, u_int32_t unit, __unused void *params)
{
	int 						error;
	ifbond_ref					ifb;
	ifnet_t						ifp;
	struct ifnet_init_eparams	bond_init;
	
	error = bond_globals_init();
	if (error != 0) {
		return (error);
	}
	
	ifb = _MALLOC(sizeof(ifbond), M_BOND, M_WAITOK | M_ZERO);
	if (ifb == NULL) {
		return (ENOMEM);
	}
	
	ifbond_retain(ifb);
	TAILQ_INIT(&ifb->ifb_port_list);
	TAILQ_INIT(&ifb->ifb_lag_list);
	ifb->ifb_key = unit + 1;
	
	/* use the interface name as the unique id for ifp recycle */
	if ((u_int32_t)snprintf(ifb->ifb_name, sizeof(ifb->ifb_name), "%s%d",
						 ifc->ifc_name, unit) >= sizeof(ifb->ifb_name)) {
		ifbond_release(ifb);
		return (EINVAL);
	}
	
	bzero(&bond_init, sizeof(bond_init));
	bond_init.ver = IFNET_INIT_CURRENT_VERSION;
	bond_init.len = sizeof (bond_init);
	bond_init.flags = IFNET_INIT_LEGACY;
	bond_init.uniqueid = ifb->ifb_name;
	bond_init.uniqueid_len = strlen(ifb->ifb_name);
	bond_init.name = ifc->ifc_name;
	bond_init.unit = unit;
	bond_init.family = IFNET_FAMILY_BOND;
	bond_init.type = IFT_IEEE8023ADLAG;
	bond_init.output = bond_output;
	bond_init.demux = ether_demux;
	bond_init.add_proto = ether_add_proto;
	bond_init.del_proto = ether_del_proto;
	bond_init.check_multi = ether_check_multi;
	bond_init.framer_extended = ether_frameout_extended;
	bond_init.ioctl = bond_ioctl;
	bond_init.set_bpf_tap = bond_set_bpf_tap;
	bond_init.detach = bond_if_free;
	bond_init.broadcast_addr = etherbroadcastaddr;
	bond_init.broadcast_len = ETHER_ADDR_LEN;
	bond_init.softc = ifb;
	error = ifnet_allocate_extended(&bond_init, &ifp);
	
	if (error) {
		ifbond_release(ifb);
		return (error);
	}
	
	ifb->ifb_ifp = ifp;
	ifnet_set_offload(ifp, 0);
	ifnet_set_addrlen(ifp, ETHER_ADDR_LEN); /* XXX ethernet specific */
	ifnet_set_flags(ifp, IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX, 0xffff);
	ifnet_set_baudrate(ifp, 0);
	ifnet_set_mtu(ifp, 0);
	
	error = ifnet_attach(ifp, NULL);
	if (error != 0) {
		ifnet_release(ifp);
		ifbond_release(ifb);
		return (error);
	}
	error = ifbond_add_slow_proto_multicast(ifb);
	if (error != 0) {
		printf("bond_clone_create(%s): "
			   "failed to add slow_proto multicast, %d\n",
			   ifb->ifb_name, error);
	}
	
	/* attach as ethernet */
	bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
	
	bond_lock();
	TAILQ_INSERT_HEAD(&g_bond->ifbond_list, ifb, ifb_bond_list);
	bond_unlock();
	
	return (0);
}

static void
bond_remove_all_interfaces(ifbond_ref ifb)
{
    bondport_ref	p;

    bond_assert_lock_held();

    /*
     * do this in reverse order to avoid re-programming the mac address
     * as each head interface is removed
     */
    while ((p = TAILQ_LAST(&ifb->ifb_port_list, port_list)) != NULL) {
	bond_remove_interface(ifb, p->po_ifp);
    }
    return;
}

static void
bond_remove(ifbond_ref ifb)
{
    bond_assert_lock_held();
    ifbond_flags_set_if_detaching(ifb);
    TAILQ_REMOVE(&g_bond->ifbond_list, ifb, ifb_bond_list);
    bond_remove_all_interfaces(ifb);
    return;
}

static void
bond_if_detach(struct ifnet * ifp)
{
    int		error;

    error = ifnet_detach(ifp);
    if (error) {
	printf("bond_if_detach %s%d: ifnet_detach failed, %d\n",
	       ifnet_name(ifp), ifnet_unit(ifp), error);
    }
	
    return;
}

static int
bond_clone_destroy(struct ifnet * ifp)
{
    ifbond_ref ifb;

    bond_lock();
    ifb = ifnet_softc(ifp);
    if (ifb == NULL || ifnet_type(ifp) != IFT_IEEE8023ADLAG) {
	bond_unlock();
	return 0;
    }
    if (ifbond_flags_if_detaching(ifb)) {
	bond_unlock();
	return 0;
    }
    bond_remove(ifb);
    bond_unlock();
    bond_if_detach(ifp);
    return 0;
}

static int 
bond_set_bpf_tap(struct ifnet * ifp, bpf_tap_mode mode, bpf_packet_func func)
{
    ifbond_ref	ifb;

    bond_lock();
    ifb = ifnet_softc(ifp);
    if (ifb == NULL || ifbond_flags_if_detaching(ifb)) {
	bond_unlock();
	return (ENODEV);
    }
    switch (mode) {
    case BPF_TAP_DISABLE:
	ifb->ifb_bpf_input = ifb->ifb_bpf_output = NULL;
	break;

    case BPF_TAP_INPUT:
	ifb->ifb_bpf_input = func;
	break;

    case BPF_TAP_OUTPUT:
	ifb->ifb_bpf_output = func;
	break;
        
    case BPF_TAP_INPUT_OUTPUT:
	ifb->ifb_bpf_input = ifb->ifb_bpf_output = func;
	break;
    default:
	break;
    }
    bond_unlock();
    return 0;
}

static uint32_t
ether_header_hash(struct ether_header * eh_p)
{
    uint32_t	h;

    /* get 32-bits from destination ether and ether type */
    h = (*((uint16_t *)&eh_p->ether_dhost[4]) << 16)
	| eh_p->ether_type;
    h ^= *((uint32_t *)&eh_p->ether_dhost[0]);
    return (h);
}

static struct mbuf *
S_mbuf_skip_to_offset(struct mbuf * m, int32_t * offset)
{
    int			len;

    len = m->m_len;
    while (*offset >= len) {
	*offset -= len;
	m = m->m_next;
	if (m == NULL) {
	    break;
	}
	len = m->m_len;
    }
    return (m);
}

#if BYTE_ORDER == BIG_ENDIAN
static __inline__ uint32_t
make_uint32(u_char c0, u_char c1, u_char c2, u_char c3)
{
    return (((uint32_t)c0 << 24) | ((uint32_t)c1 << 16) 
	    | ((uint32_t)c2 << 8) | (uint32_t)c3);
}
#else /* BYTE_ORDER == LITTLE_ENDIAN */
static __inline__ uint32_t
make_uint32(u_char c0, u_char c1, u_char c2, u_char c3)
{
    return (((uint32_t)c3 << 24) | ((uint32_t)c2 << 16) 
	    | ((uint32_t)c1 << 8) | (uint32_t)c0);
}
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

static int
S_mbuf_copy_uint32(struct mbuf * m, int32_t offset, uint32_t * val)
{
    struct mbuf *	current;
    u_char *		current_data;
    struct mbuf *	next;
    u_char *		next_data;
    int			space_current;

    current = S_mbuf_skip_to_offset(m, &offset);
    if (current == NULL) {
	return (1);
    }
    current_data = mtod(current, u_char *) + offset;
    space_current = current->m_len - offset;
    if (space_current >= (int)sizeof(uint32_t)) {
	*val = *((uint32_t *)current_data);
	return (0);
    }
    next = current->m_next;
    if (next == NULL || (next->m_len + space_current) < (int)sizeof(uint32_t)) {
	return (1);
    }
    next_data = mtod(next, u_char *);
    switch (space_current) {
    case 1:
	*val = make_uint32(current_data[0], next_data[0],
			   next_data[1], next_data[2]);
	break;
    case 2:
	*val = make_uint32(current_data[0], current_data[1],
			   next_data[0], next_data[1]);
	break;
    default:
	*val = make_uint32(current_data[0], current_data[1],
			   current_data[2], next_data[0]);
	break;
    }
    return (0);
}

#define IP_SRC_OFFSET (offsetof(struct ip, ip_src) - offsetof(struct ip, ip_p))
#define IP_DST_OFFSET (offsetof(struct ip, ip_dst) - offsetof(struct ip, ip_p))

static uint32_t
ip_header_hash(struct mbuf * m)
{
    u_char *		data;
    struct in_addr	ip_dst;
    struct in_addr	ip_src;
    u_char		ip_p;
    int32_t		offset;
    struct mbuf *	orig_m = m;

    /* find the IP protocol field relative to the start of the packet */
    offset = offsetof(struct ip, ip_p) + sizeof(struct ether_header);
    m = S_mbuf_skip_to_offset(m, &offset);
    if (m == NULL || m->m_len < 1) {
	goto bad_ip_packet;
    }
    data = mtod(m, u_char *) + offset;
    ip_p = *data;

    /* find the IP src relative to the IP protocol */
    if ((m->m_len - offset) 
	>= (int)(IP_SRC_OFFSET + sizeof(struct in_addr) * 2)) {
	/* this should be the normal case */
	ip_src = *(struct in_addr *)(data + IP_SRC_OFFSET);
	ip_dst = *(struct in_addr *)(data + IP_DST_OFFSET);
    }
    else {
	if (S_mbuf_copy_uint32(m, offset + IP_SRC_OFFSET,
			       (uint32_t *)&ip_src.s_addr)) {
	    goto bad_ip_packet;
	}
	if (S_mbuf_copy_uint32(m, offset + IP_DST_OFFSET,
			       (uint32_t *)&ip_dst.s_addr)) {
	    goto bad_ip_packet;
	}
    }
    return (ntohl(ip_dst.s_addr) ^ ntohl(ip_src.s_addr) ^ ((uint32_t)ip_p));

 bad_ip_packet:
    return (ether_header_hash(mtod(orig_m, struct ether_header *)));
}

#define IP6_ADDRS_LEN 	(sizeof(struct in6_addr) * 2)
static uint32_t
ipv6_header_hash(struct mbuf * m)
{
    u_char *		data;
    int			i;
    int32_t		offset;
    struct mbuf *	orig_m = m;
    uint32_t *		scan;
    uint32_t		val;

    /* find the IP protocol field relative to the start of the packet */
    offset = offsetof(struct ip6_hdr, ip6_src) + sizeof(struct ether_header);
    m = S_mbuf_skip_to_offset(m, &offset);
    if (m == NULL) {
	goto bad_ipv6_packet;
    }
    data = mtod(m, u_char *) + offset;
    val = 0;
    if ((m->m_len - offset) >= (int)IP6_ADDRS_LEN) {
	/* this should be the normal case */
	for (i = 0, scan = (uint32_t *)data;
	     i < (int)(IP6_ADDRS_LEN / sizeof(uint32_t));
	     i++, scan++) {
	    val ^= *scan;
	}
    }
    else {
	for (i = 0; i < (int)(IP6_ADDRS_LEN / sizeof(uint32_t)); i++) {
	    uint32_t	tmp;
	    if (S_mbuf_copy_uint32(m, offset + i * sizeof(uint32_t),
				   (uint32_t *)&tmp)) {
		goto bad_ipv6_packet;
	    }
	    val ^= tmp;
	}
    }
    return (ntohl(val));

 bad_ipv6_packet:
    return (ether_header_hash(mtod(orig_m, struct ether_header *)));
}

static int
bond_output(struct ifnet * ifp, struct mbuf * m)
{
    bpf_packet_func		bpf_func;
    uint32_t			h;
    ifbond_ref			ifb;
    struct ifnet *		port_ifp = NULL;
    int				err;
    struct flowadv		adv = { FADV_SUCCESS };
	
    if (m == 0) {
	return (0);
    }
    if ((m->m_flags & M_PKTHDR) == 0) {
	m_freem(m);
	return (0);
    }
    if (m->m_pkthdr.pkt_flowid != 0) {
	h = m->m_pkthdr.pkt_flowid;
    }
    else {
	struct ether_header *	eh_p;

	eh_p = mtod(m, struct ether_header *);
	switch (ntohs(eh_p->ether_type)) {
	case ETHERTYPE_IP:
	    h = ip_header_hash(m);
	    break;
	case ETHERTYPE_IPV6:
	    h = ipv6_header_hash(m);
	    break;
	default:
	    h = ether_header_hash(eh_p);
	    break;
	}
    }
    bond_lock();
    ifb = ifnet_softc(ifp);
    if (ifb == NULL || ifbond_flags_if_detaching(ifb)
	|| ifb->ifb_distributing_count == 0) {
	goto done;
    }
    h %= ifb->ifb_distributing_count;
    port_ifp = ifb->ifb_distributing_array[h]->po_ifp;
    bpf_func = ifb->ifb_bpf_output;
    bond_unlock();

    if (m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) {
	(void)ifnet_stat_increment_out(ifp, 1, 
				       m->m_pkthdr.len + ETHER_VLAN_ENCAP_LEN,
				       0);
    } else {
	(void)ifnet_stat_increment_out(ifp, 1, m->m_pkthdr.len, 0);
    }
    bond_bpf_output(ifp, m, bpf_func);

    err = dlil_output(port_ifp, PF_BOND, m, NULL, NULL, 1, &adv);

    if (err == 0) {
	if (adv.code == FADV_FLOW_CONTROLLED) {
	    err = EQFULL;
	} else if (adv.code == FADV_SUSPENDED) {
	    err = EQSUSPENDED;
	}
    }

    return (err);

 done:
    bond_unlock();
    m_freem(m);
    return (0);
}

static bondport_ref
ifbond_lookup_port(ifbond_ref ifb, struct ifnet * port_ifp)
{
    bondport_ref	p;
    TAILQ_FOREACH(p, &ifb->ifb_port_list, po_port_list) {
	if (p->po_ifp == port_ifp) {
	    return (p);
	}
    }
    return (NULL);
}

static bondport_ref
bond_lookup_port(struct ifnet * port_ifp)
{
    ifbond_ref		ifb;
    bondport_ref	port;

    TAILQ_FOREACH(ifb, &g_bond->ifbond_list, ifb_bond_list) {
	port = ifbond_lookup_port(ifb, port_ifp);
	if (port != NULL) {
	    return (port);
	}
    }
    return (NULL);
}

static void
bond_receive_lacpdu(struct mbuf * m, struct ifnet * port_ifp)
{
    struct ifnet *		bond_ifp = NULL;
    ifbond_ref			ifb;
    int				event_code = 0;
    bondport_ref		p;

    bond_lock();
    if ((ifnet_eflags(port_ifp) & IFEF_BOND) == 0) {
	goto done;
    }
    p = bond_lookup_port(port_ifp);
    if (p == NULL) {
	goto done;
    }
    if (p->po_enabled == 0) {
	goto done;
    }
    ifb = p->po_bond;
    if (ifb->ifb_mode != IF_BOND_MODE_LACP) {
	goto done;
    }
    bondport_receive_lacpdu(p, (lacpdu_ref)m->m_data);
    if (ifbond_selection(ifb)) {
	event_code = (ifb->ifb_active_lag == NULL) 
	    ? KEV_DL_LINK_OFF 
	    : KEV_DL_LINK_ON;
	/* XXX need to take a reference on bond_ifp */
	bond_ifp = ifb->ifb_ifp;
	ifb->ifb_last_link_event = event_code;
    }
    else {
	event_code = (ifb->ifb_active_lag == NULL) 
	    ? KEV_DL_LINK_OFF 
	    : KEV_DL_LINK_ON;
	if (event_code != ifb->ifb_last_link_event) {
	    if (g_bond->verbose) {
		timestamp_printf("%s: (receive) generating LINK event\n",
				 ifb->ifb_name);
	    }
	    bond_ifp = ifb->ifb_ifp;
	    ifb->ifb_last_link_event = event_code;
	}
    }

 done:
    bond_unlock();
    if (bond_ifp != NULL) {
	interface_link_event(bond_ifp, event_code);
    }
    m_freem(m);
    return;
}

static void
bond_receive_la_marker_pdu(struct mbuf * m, struct ifnet * port_ifp)
{
    la_marker_pdu_ref		marker_p;
    bondport_ref		p;

    marker_p = (la_marker_pdu_ref)(m->m_data + ETHER_HDR_LEN);
    if (marker_p->lm_marker_tlv_type != LA_MARKER_TLV_TYPE_MARKER) {
	goto failed;
    }
    bond_lock();
    if ((ifnet_eflags(port_ifp) & IFEF_BOND) == 0) {
	bond_unlock();
	goto failed;
    }
    p = bond_lookup_port(port_ifp);
    if (p == NULL || p->po_enabled == 0
	|| p->po_bond->ifb_mode != IF_BOND_MODE_LACP) {
	bond_unlock();
	goto failed;
    }
    /* echo back the same packet as a marker response */
    marker_p->lm_marker_tlv_type = LA_MARKER_TLV_TYPE_MARKER_RESPONSE;
    bondport_slow_proto_transmit(p, (packet_buffer_ref)m);
    bond_unlock();
    return;

 failed:
    m_freem(m);
    return;
}

static int
bond_input(ifnet_t port_ifp, __unused protocol_family_t protocol, mbuf_t m,
		   char * frame_header)
{
    bpf_packet_func		bpf_func;
    const struct ether_header *	eh_p;
    ifbond_ref			ifb;
    struct ifnet *		ifp;	
    bondport_ref		p;

    eh_p = (const struct ether_header *)frame_header;
    if ((m->m_flags & M_MCAST) != 0
	&& bcmp(eh_p->ether_dhost, &slow_proto_multicast,
		sizeof(eh_p->ether_dhost)) == 0
	&& ntohs(eh_p->ether_type) == IEEE8023AD_SLOW_PROTO_ETHERTYPE) {
	u_char 	subtype = *mtod(m, u_char *);

	if (subtype == IEEE8023AD_SLOW_PROTO_SUBTYPE_LACP) {
	    if (m->m_pkthdr.len < (int)offsetof(lacpdu, la_reserved)) {
		m_freem(m);
		return (0);
	    }
	    /* send to lacp */
	    if (m->m_len < (int)offsetof(lacpdu, la_reserved)) {
		m = m_pullup(m, offsetof(lacpdu, la_reserved));
		if (m == NULL) {
		    return (0);
		}
	    }
	    bond_receive_lacpdu(m, port_ifp);
	    return (0);
	}
	else if (subtype == IEEE8023AD_SLOW_PROTO_SUBTYPE_LA_MARKER_PROTOCOL) {
	    int		min_size;

	    /* restore the ethernet header pointer in the mbuf */
	    m->m_pkthdr.len += ETHER_HDR_LEN;
	    m->m_data -= ETHER_HDR_LEN;
	    m->m_len += ETHER_HDR_LEN;
	    min_size = ETHER_HDR_LEN + offsetof(la_marker_pdu, lm_reserved);
	    if (m->m_pkthdr.len < min_size) {
		m_freem(m);
		return (0);
	    }
	    /* send to lacp */
	    if (m->m_len < min_size) {
		m = m_pullup(m, min_size);
		if (m == NULL) {
		    return (0);
		}
	    }
	    /* send to marker responder */
	    bond_receive_la_marker_pdu(m, port_ifp);
	    return (0);
	}
	else if (subtype == 0 
		 || subtype > IEEE8023AD_SLOW_PROTO_SUBTYPE_RESERVED_END) {
	    /* invalid subtype, discard the frame */
	    m_freem(m);
	    return (0);
	}
    }
    bond_lock();
    if ((ifnet_eflags(port_ifp) & IFEF_BOND) == 0) {
	goto done;
    }
    p = bond_lookup_port(port_ifp);
    if (p == NULL || bondport_collecting(p) == 0) {
	goto done;
    }

    /* make the packet appear as if it arrived on the bonded interface */
    ifb = p->po_bond;
    ifp = ifb->ifb_ifp;
    bpf_func = ifb->ifb_bpf_input;
    bond_unlock();

    if (m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) {
	(void)ifnet_stat_increment_in(ifp, 1, 
				      (m->m_pkthdr.len + ETHER_HDR_LEN 
				       + ETHER_VLAN_ENCAP_LEN), 0);
    }
    else {
	(void)ifnet_stat_increment_in(ifp, 1, 
				      (m->m_pkthdr.len + ETHER_HDR_LEN), 0);
    }
    m->m_pkthdr.rcvif = ifp;
    bond_bpf_input(ifp, m, eh_p, bpf_func);
    m->m_pkthdr.pkt_hdr = frame_header;
    dlil_input_packet_list(ifp, m);
    return 0;

 done:
    bond_unlock();
    m_freem(m);
    return (0);
}

static __inline__ const char *
bondport_get_name(bondport_ref p)
{
    return (p->po_name);
}

static __inline__ int
bondport_get_index(bondport_ref p)
{
    return (ifnet_index(p->po_ifp));
}

static void
bondport_slow_proto_transmit(bondport_ref p, packet_buffer_ref buf)
{
    struct ether_header *	eh_p;
    int				error;

    /* packet_buffer_allocate leaves room for ethernet header */
    eh_p = mtod(buf, struct ether_header *);
    bcopy(&slow_proto_multicast, &eh_p->ether_dhost, sizeof(eh_p->ether_dhost));
    bcopy(&p->po_saved_addr, eh_p->ether_shost, sizeof(eh_p->ether_shost));
    eh_p->ether_type = htons(IEEE8023AD_SLOW_PROTO_ETHERTYPE);
    error = ifnet_output_raw(p->po_ifp, PF_BOND, buf);
    if (error != 0) {
	printf("bondport_slow_proto_transmit(%s) failed %d\n",
	       bondport_get_name(p), error);
    }
    return;
}

static void
bondport_timer_process_func(devtimer_ref timer, 
			    devtimer_process_func_event event)
{
    bondport_ref	p;

    switch (event) {
    case devtimer_process_func_event_lock:
	bond_lock();
	devtimer_retain(timer);
	break;
    case devtimer_process_func_event_unlock:
	if (devtimer_valid(timer)) {
	    /* as long as the devtimer is valid, we can look at arg0 */
	    int			event_code = 0;
	    struct ifnet *	bond_ifp = NULL;

	    p = (bondport_ref)devtimer_arg0(timer);
	    if (ifbond_selection(p->po_bond)) {
		event_code = (p->po_bond->ifb_active_lag == NULL) 
		    ? KEV_DL_LINK_OFF 
		    : KEV_DL_LINK_ON;
		/* XXX need to take a reference on bond_ifp */
		bond_ifp = p->po_bond->ifb_ifp;
		p->po_bond->ifb_last_link_event = event_code;
	    }
	    else {
		event_code = (p->po_bond->ifb_active_lag == NULL) 
		    ? KEV_DL_LINK_OFF 
		    : KEV_DL_LINK_ON;
		if (event_code != p->po_bond->ifb_last_link_event) {
		    if (g_bond->verbose) {
			timestamp_printf("%s: (timer) generating LINK event\n",
					 p->po_bond->ifb_name);
		    }
		    bond_ifp = p->po_bond->ifb_ifp;
		    p->po_bond->ifb_last_link_event = event_code;
		}
	    }
	    devtimer_release(timer);
	    bond_unlock();
	    if (bond_ifp != NULL) {
		interface_link_event(bond_ifp, event_code);
	    }
	}
	else {
	    /* timer is going away */
	    devtimer_release(timer);
	    bond_unlock();
	}
	break;
    default:
	break;
    }
}

static bondport_ref
bondport_create(struct ifnet * port_ifp, lacp_port_priority priority,
		int active, int short_timeout, int * ret_error)
{
    int				error = 0;
    bondport_ref		p = NULL;
    lacp_actor_partner_state	s;

    *ret_error = 0;
    p = _MALLOC(sizeof(*p), M_BOND, M_WAITOK | M_ZERO);
    if (p == NULL) {
	*ret_error = ENOMEM;
	return (NULL);
    }
    multicast_list_init(&p->po_multicast);
    if ((u_int32_t)snprintf(p->po_name, sizeof(p->po_name), "%s%d",
			 ifnet_name(port_ifp), ifnet_unit(port_ifp)) 
	>= sizeof(p->po_name)) {
	printf("if_bond: name too large\n");
	*ret_error = EINVAL;
	goto failed;
    }
    error = siocgifdevmtu(port_ifp, &p->po_devmtu);
    if (error != 0) {
	printf("if_bond: SIOCGIFDEVMTU %s failed, %d\n",
	       bondport_get_name(p), error);
	goto failed;
    }
    /* remember the current interface MTU so it can be restored */
    p->po_devmtu.ifdm_current = ifnet_mtu(port_ifp);
    p->po_ifp = port_ifp;
    p->po_media_info = interface_media_info(port_ifp);
    p->po_current_while_timer = devtimer_create(bondport_timer_process_func, p);
    if (p->po_current_while_timer == NULL) {
	*ret_error = ENOMEM;
	goto failed;
    }
    p->po_periodic_timer = devtimer_create(bondport_timer_process_func, p);
    if (p->po_periodic_timer == NULL) {
	*ret_error = ENOMEM;
	goto failed;
    }
    p->po_wait_while_timer = devtimer_create(bondport_timer_process_func, p);
    if (p->po_wait_while_timer == NULL) {
	*ret_error = ENOMEM;
	goto failed;
    }
    p->po_transmit_timer = devtimer_create(bondport_timer_process_func, p);
    if (p->po_transmit_timer == NULL) {
	*ret_error = ENOMEM;
	goto failed;
    }
    p->po_receive_state = ReceiveState_none;
    p->po_mux_state = MuxState_none;
    p->po_priority = priority;
    s = 0;
    s = lacp_actor_partner_state_set_aggregatable(s);
    if (short_timeout) {
	s = lacp_actor_partner_state_set_short_timeout(s);
    }
    if (active) {
	s = lacp_actor_partner_state_set_active_lacp(s);
    }
    p->po_actor_state = s;
    return (p);

 failed:
    bondport_free(p);
    return (NULL);
}

static void
bondport_start(bondport_ref p)
{
    bondport_receive_machine(p, LAEventStart, NULL);
    bondport_mux_machine(p, LAEventStart, NULL);
    bondport_periodic_transmit_machine(p, LAEventStart, NULL);
    bondport_transmit_machine(p, LAEventStart, NULL);
    return;
}

/*
 * Function: bondport_invalidate_timers
 * Purpose:
 *   Invalidate all of the timers for the bondport.
 */
static void
bondport_invalidate_timers(bondport_ref p)
{
    devtimer_invalidate(p->po_current_while_timer);
    devtimer_invalidate(p->po_periodic_timer);
    devtimer_invalidate(p->po_wait_while_timer);
    devtimer_invalidate(p->po_transmit_timer);
}

/*
 * Function: bondport_cancel_timers
 * Purpose:
 *   Cancel all of the timers for the bondport.
 */
static void
bondport_cancel_timers(bondport_ref p)
{
    devtimer_cancel(p->po_current_while_timer);
    devtimer_cancel(p->po_periodic_timer);
    devtimer_cancel(p->po_wait_while_timer);
    devtimer_cancel(p->po_transmit_timer);
}

static void
bondport_free(bondport_ref p)
{
    multicast_list_remove(&p->po_multicast);
    devtimer_release(p->po_current_while_timer);
    devtimer_release(p->po_periodic_timer);
    devtimer_release(p->po_wait_while_timer);
    devtimer_release(p->po_transmit_timer);
    FREE(p, M_BOND);
    return;
}

#define BOND_ADD_PROGRESS_IN_LIST		0x1
#define BOND_ADD_PROGRESS_PROTO_ATTACHED	0x2
#define BOND_ADD_PROGRESS_LLADDR_SET		0x4
#define BOND_ADD_PROGRESS_MTU_SET		0x8

static __inline__ int
bond_device_mtu(struct ifnet * ifp, ifbond_ref ifb)
{
    return (((int)ifnet_mtu(ifp) > ifb->ifb_altmtu) 
	    ? (int)ifnet_mtu(ifp) : ifb->ifb_altmtu);
}

static int
bond_add_interface(struct ifnet * ifp, struct ifnet * port_ifp)
{
    int				devmtu;
    int				error = 0;
    int				event_code = 0;
    int				first = FALSE;
    ifbond_ref			ifb;
    bondport_ref *		new_array = NULL;
    bondport_ref *		old_array = NULL;
    bondport_ref 		p;
    int				progress = 0;

    /* pre-allocate space for new port */
    p = bondport_create(port_ifp, 0x8000, 1, 0, &error);
    if (p == NULL) {
	return (error);
    }
    bond_lock();
    ifb = (ifbond_ref)ifnet_softc(ifp);
    if (ifb == NULL || ifbond_flags_if_detaching(ifb)) {
	bond_unlock();
	bondport_free(p);
	return ((ifb == NULL ? EOPNOTSUPP : EBUSY));
    }

    /* make sure this interface can handle our current MTU */
    devmtu = bond_device_mtu(ifp, ifb);
    if (devmtu != 0 
	&& (devmtu > p->po_devmtu.ifdm_max || devmtu < p->po_devmtu.ifdm_min)) {
	bond_unlock();
	printf("if_bond: interface %s doesn't support mtu %d",
	       bondport_get_name(p), devmtu);
	bondport_free(p);
	return (EINVAL);
    }

    /* make sure ifb doesn't get de-allocated while we wait */
    ifbond_retain(ifb);

    /* wait for other add or remove to complete */
    ifbond_wait(ifb, "bond_add_interface");

    if (ifbond_flags_if_detaching(ifb)) {
	/* someone destroyed the bond while we were waiting */
	error = EBUSY;
	goto signal_done;
    }
    if (bond_lookup_port(port_ifp) != NULL) {
	/* port is already part of a bond */
	error = EBUSY;
	goto signal_done;
    }
    ifnet_lock_exclusive(port_ifp);
    if ((ifnet_eflags(port_ifp) & (IFEF_VLAN | IFEF_BOND)) != 0) {
	/* interface already has VLAN's, or is part of bond */
	ifnet_lock_done(port_ifp);
	error = EBUSY;
	goto signal_done;
    }

    /* mark the interface busy */
    /* can't use ifnet_set_eflags because that takes the lock */
    port_ifp->if_eflags |= IFEF_BOND;
    ifnet_lock_done(port_ifp);

    if (TAILQ_EMPTY(&ifb->ifb_port_list)) {
	ifnet_set_offload(ifp, ifnet_offload(port_ifp));
	ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);
	if (ifbond_flags_lladdr(ifb) == FALSE) {
	    first = TRUE;
	}
    } else {
	ifnet_offload_t		ifp_offload;
	ifnet_offload_t		port_ifp_offload;

	ifp_offload = ifnet_offload(ifp);
	port_ifp_offload = ifnet_offload(port_ifp);
	if (ifp_offload != port_ifp_offload) {
	    ifnet_offload_t	offload;

	    offload = ifp_offload & port_ifp_offload;
	    printf("bond_add_interface(%s, %s)  "
		   "hwassist values don't match 0x%x != 0x%x, using 0x%x instead\n",
		   ifb->ifb_name, bondport_get_name(p),
		   ifp_offload, port_ifp_offload, offload);
	    /*
	     * XXX
	     * if the bond has VLAN's, we can't simply change the hwassist
	     * field behind its back: this needs work
	     */
	    ifnet_set_offload(ifp, offload);
	}
    }
    p->po_bond = ifb;

    /* remember the port's ethernet address so it can be restored */
    ether_addr_copy(&p->po_saved_addr, IF_LLADDR(port_ifp));

    /* add it to the list of ports */
    TAILQ_INSERT_TAIL(&ifb->ifb_port_list, p, po_port_list);
    ifb->ifb_port_count++;

    /* set the default MTU */
    if (ifnet_mtu(ifp) == 0) {
	ifnet_set_mtu(ifp, ETHERMTU);
    }
    bond_unlock();


    /* first port added to bond determines bond's ethernet address */
    if (first) {
	ifnet_set_lladdr_and_type(ifp, IF_LLADDR(port_ifp), ETHER_ADDR_LEN,
				  IFT_ETHER);
    }

    progress |= BOND_ADD_PROGRESS_IN_LIST;

    /* allocate a larger distributing array */
    new_array = (bondport_ref *)
	_MALLOC(sizeof(*new_array) * ifb->ifb_port_count, M_BOND, M_WAITOK);
    if (new_array == NULL) {
	error = ENOMEM;
	goto failed;
    }

    /* attach our BOND "protocol" to the interface */
    error = bond_attach_protocol(port_ifp);
    if (error) {
	goto failed;
    }
    progress |= BOND_ADD_PROGRESS_PROTO_ATTACHED;

    /* set the interface MTU */
    devmtu = bond_device_mtu(ifp, ifb);
    error = siocsifmtu(port_ifp, devmtu);
    if (error != 0) {
	printf("bond_add_interface(%s, %s):"
	       " SIOCSIFMTU %d failed %d\n", 
	       ifb->ifb_name, bondport_get_name(p), devmtu, error);
	goto failed;
    }
    progress |= BOND_ADD_PROGRESS_MTU_SET;

    /* program the port with our multicast addresses */
    error = multicast_list_program(&p->po_multicast, ifp, port_ifp);
    if (error) {
	printf("bond_add_interface(%s, %s):"
	       " multicast_list_program failed %d\n", 
	       ifb->ifb_name, bondport_get_name(p), error);
	goto failed;
    }

    /* mark the interface up */
    ifnet_set_flags(port_ifp, IFF_UP, IFF_UP);

    error = ifnet_ioctl(port_ifp, 0, SIOCSIFFLAGS, NULL);
    if (error != 0) {
	printf("bond_add_interface(%s, %s): SIOCSIFFLAGS failed %d\n", 
	       ifb->ifb_name, bondport_get_name(p), error);
	goto failed;
    }

    /* re-program the port's ethernet address */
    error = if_siflladdr(port_ifp, 
			 (const struct ether_addr *)IF_LLADDR(ifp));
    if (error != 0) {
	/* port doesn't support setting the link address */
	printf("bond_add_interface(%s, %s): if_siflladdr failed %d\n", 
	       ifb->ifb_name, bondport_get_name(p), error);
	goto failed;
    }
    progress |= BOND_ADD_PROGRESS_LLADDR_SET;

    bond_lock();

    /* no failures past this point */
    p->po_enabled = 1;

    /* copy the contents of the existing distributing array */
    if (ifb->ifb_distributing_count) {
	bcopy(ifb->ifb_distributing_array, new_array, 
	      sizeof(*new_array) * ifb->ifb_distributing_count);
    }
    old_array = ifb->ifb_distributing_array;
    ifb->ifb_distributing_array = new_array;

    if (ifb->ifb_mode == IF_BOND_MODE_LACP) {
	bondport_start(p);

	/* check if we need to generate a link status event */
	if (ifbond_selection(ifb)) {
	    event_code = (ifb->ifb_active_lag == NULL) 
		? KEV_DL_LINK_OFF 
		: KEV_DL_LINK_ON;
	    ifb->ifb_last_link_event = event_code;
	}
    }
    else {
	/* are we adding the first distributing interface? */
	if (media_active(&p->po_media_info)) {
	    if (ifb->ifb_distributing_count == 0) {
		ifb->ifb_last_link_event = event_code = KEV_DL_LINK_ON;
	    }
	    bondport_enable_distributing(p);
	}
	else {
	    bondport_disable_distributing(p);
	}
    }
    /* clear the busy state, and wakeup anyone waiting */
    ifbond_signal(ifb, "bond_add_interface");
    bond_unlock();
    if (event_code != 0) {
	interface_link_event(ifp, event_code);
    }
    if (old_array != NULL) {
	FREE(old_array, M_BOND);
    }
    return 0;

 failed:
    bond_assert_lock_not_held();

    /* if this was the first port to be added, clear our address */
    if (first) {
	ifnet_set_lladdr_and_type(ifp, NULL, 0, IFT_IEEE8023ADLAG);
    }

    if (new_array != NULL) {
	FREE(new_array, M_BOND);
    }
    if ((progress & BOND_ADD_PROGRESS_LLADDR_SET) != 0) {
	int	error1;

	error1 = if_siflladdr(port_ifp, &p->po_saved_addr);
	if (error1 != 0) {
	    printf("bond_add_interface(%s, %s): if_siflladdr failed %d\n", 
		   ifb->ifb_name, bondport_get_name(p), error1);
	}
    }
    if ((progress & BOND_ADD_PROGRESS_PROTO_ATTACHED) != 0) {
	(void)bond_detach_protocol(port_ifp);
    }
    if ((progress & BOND_ADD_PROGRESS_MTU_SET) != 0) {
	int error1;

	error1 = siocsifmtu(port_ifp, p->po_devmtu.ifdm_current);
	if (error1 != 0) {
	    printf("bond_add_interface(%s, %s): SIOCSIFMTU %d failed %d\n", 
		   ifb->ifb_name, bondport_get_name(p),
		   p->po_devmtu.ifdm_current, error1);
	}
    }
    bond_lock();
    if ((progress & BOND_ADD_PROGRESS_IN_LIST) != 0) {
	TAILQ_REMOVE(&ifb->ifb_port_list, p, po_port_list);
	ifb->ifb_port_count--;
    }
    ifnet_set_eflags(ifp, 0, IFEF_BOND);
    if (TAILQ_EMPTY(&ifb->ifb_port_list)) {
	ifb->ifb_altmtu = 0;
	ifnet_set_mtu(ifp, 0);
	ifnet_set_offload(ifp, 0);
    }

 signal_done:
    ifbond_signal(ifb, "bond_add_interface");
    bond_unlock();
    ifbond_release(ifb);
    bondport_free(p);
    return (error);
}

static int
bond_remove_interface(ifbond_ref ifb, struct ifnet * port_ifp)
{
    int				active_lag = 0;
    int 			error = 0;
    int				event_code = 0;
    bondport_ref		head_port;
    struct ifnet *		ifp;
    int				last = FALSE;
    int				new_link_address = FALSE;
    bondport_ref 		p;
    lacp_actor_partner_state	s;
    int				was_distributing;

    bond_assert_lock_held();

    ifbond_retain(ifb);
    ifbond_wait(ifb, "bond_remove_interface");

    p = ifbond_lookup_port(ifb, port_ifp);
    if (p == NULL) {
	error = ENXIO;
	/* it got removed by another thread */
	goto signal_done;
    }

    /* de-select it and remove it from the lists */
    was_distributing = bondport_flags_distributing(p);
    bondport_disable_distributing(p);
    if (ifb->ifb_mode == IF_BOND_MODE_LACP) {
	bondport_set_selected(p, SelectedState_UNSELECTED);
	active_lag = bondport_remove_from_LAG(p);
	/* invalidate timers here while holding the bond_lock */
	bondport_invalidate_timers(p);

	/* announce that we're Individual now */
	s = p->po_actor_state;
	s = lacp_actor_partner_state_set_individual(s);
	s = lacp_actor_partner_state_set_not_collecting(s);
	s = lacp_actor_partner_state_set_not_distributing(s);
	s = lacp_actor_partner_state_set_out_of_sync(s);
	p->po_actor_state = s;
	bondport_flags_set_ntt(p);
    }

    TAILQ_REMOVE(&ifb->ifb_port_list, p, po_port_list);
    ifb->ifb_port_count--;

    ifp = ifb->ifb_ifp;
    head_port = TAILQ_FIRST(&ifb->ifb_port_list);
    if (head_port == NULL) {
	ifnet_set_flags(ifp, 0, IFF_RUNNING);
	if (ifbond_flags_lladdr(ifb) == FALSE) {
	    last = TRUE;
	}
	ifnet_set_offload(ifp, 0);
	ifnet_set_mtu(ifp, 0);
	ifb->ifb_altmtu = 0;
    } else if (ifbond_flags_lladdr(ifb) == FALSE
	       && bcmp(&p->po_saved_addr, IF_LLADDR(ifp), 
		       ETHER_ADDR_LEN) == 0) {
	new_link_address = TRUE;
    }
    /* check if we need to generate a link status event */
    if (ifb->ifb_mode == IF_BOND_MODE_LACP ) {
	if (ifbond_selection(ifb) || active_lag) {
	    event_code = (ifb->ifb_active_lag == NULL) 
		? KEV_DL_LINK_OFF 
		: KEV_DL_LINK_ON;
	    ifb->ifb_last_link_event = event_code;
	}
	bondport_transmit_machine(p, LAEventStart,
				  TRANSMIT_MACHINE_TX_IMMEDIATE);
    }
    else {
	/* are we removing the last distributing interface? */
	if (was_distributing && ifb->ifb_distributing_count == 0) {
	    ifb->ifb_last_link_event = event_code = KEV_DL_LINK_OFF;
	}
    }

    bond_unlock();

    if (last) {
	ifnet_set_lladdr_and_type(ifp, NULL, 0, IFT_IEEE8023ADLAG);
    }
    else if (new_link_address) {
	struct ifnet *	scan_ifp;
	bondport_ref	scan_port;

	/* ifbond_wait() allows port list traversal without holding the lock */

	/* this port gave the bond its ethernet address, switch to new one */
	ifnet_set_lladdr_and_type(ifp,
				  &head_port->po_saved_addr, ETHER_ADDR_LEN,
				  IFT_ETHER);

	/* re-program each port with the new link address */
	TAILQ_FOREACH(scan_port, &ifb->ifb_port_list, po_port_list) {
	    scan_ifp = scan_port->po_ifp;

	    error = if_siflladdr(scan_ifp,
				 (const struct ether_addr *) IF_LLADDR(ifp));
	    if (error != 0) {
		printf("bond_remove_interface(%s, %s): "
		       "if_siflladdr (%s) failed %d\n", 
		       ifb->ifb_name, bondport_get_name(p),
		       bondport_get_name(scan_port), error);
	    }
	}
    }

    /* restore the port's ethernet address */
    error = if_siflladdr(port_ifp, &p->po_saved_addr);
    if (error != 0) {
	printf("bond_remove_interface(%s, %s): if_siflladdr failed %d\n", 
	       ifb->ifb_name, bondport_get_name(p), error);
    }

    /* restore the port's MTU */
    error = siocsifmtu(port_ifp, p->po_devmtu.ifdm_current);
    if (error != 0) {
	printf("bond_remove_interface(%s, %s): SIOCSIFMTU %d failed %d\n", 
	       ifb->ifb_name, bondport_get_name(p), 
	       p->po_devmtu.ifdm_current, error);
    }

    /* remove the bond "protocol" */
    bond_detach_protocol(port_ifp);

    /* generate link event */
    if (event_code != 0) {
	interface_link_event(ifp, event_code);
    }

    bond_lock();
    bondport_free(p);
    ifnet_set_eflags(port_ifp, 0, IFEF_BOND);
    /* release this bondport's reference to the ifbond */
    ifbond_release(ifb);

 signal_done:
    ifbond_signal(ifb, "bond_remove_interface");
    ifbond_release(ifb);
    return (error);
}

static void
bond_set_lacp_mode(ifbond_ref ifb)
{
    bondport_ref		p;

    TAILQ_FOREACH(p, &ifb->ifb_port_list, po_port_list) {
	bondport_disable_distributing(p);
	bondport_start(p);
    }
    return;
}

static void
bond_set_static_mode(ifbond_ref ifb)
{
    bondport_ref		p;
    lacp_actor_partner_state	s;

    TAILQ_FOREACH(p, &ifb->ifb_port_list, po_port_list) {
	bondport_disable_distributing(p);
	bondport_set_selected(p, SelectedState_UNSELECTED);
	(void)bondport_remove_from_LAG(p);
	bondport_cancel_timers(p);

	/* announce that we're Individual now */
	s = p->po_actor_state;
	s = lacp_actor_partner_state_set_individual(s);
	s = lacp_actor_partner_state_set_not_collecting(s);
	s = lacp_actor_partner_state_set_not_distributing(s);
	s = lacp_actor_partner_state_set_out_of_sync(s);
	p->po_actor_state = s;
	bondport_flags_set_ntt(p);
	bondport_transmit_machine(p, LAEventStart,
				  TRANSMIT_MACHINE_TX_IMMEDIATE);
	/* clear state */
	p->po_actor_state = 0;
	bzero(&p->po_partner_state, sizeof(p->po_partner_state));

	if (media_active(&p->po_media_info)) {
	    bondport_enable_distributing(p);
	}
	else {
	    bondport_disable_distributing(p);
	}
    }
    return;
}

static int
bond_set_mode(struct ifnet * ifp, int mode)
{
    int				error = 0;
    int				event_code = 0;
    ifbond_ref			ifb;

    bond_lock();
    ifb = (ifbond_ref)ifnet_softc(ifp);
    if (ifb == NULL || ifbond_flags_if_detaching(ifb)) {
	bond_unlock();
	return ((ifb == NULL) ? EOPNOTSUPP : EBUSY);
    }
    if (ifb->ifb_mode == mode) {
	bond_unlock();
	return (0);
    }

    ifbond_retain(ifb);
    ifbond_wait(ifb, "bond_set_mode");

    /* verify (again) that the mode is actually different */
    if (ifb->ifb_mode == mode) {
	/* nothing to do */
	goto signal_done;
    }

    ifb->ifb_mode = mode;
    if (mode == IF_BOND_MODE_LACP) {
	bond_set_lacp_mode(ifb);
	
	/* check if we need to generate a link status event */
	if (ifbond_selection(ifb)) {
	    event_code = (ifb->ifb_active_lag == NULL) 
		? KEV_DL_LINK_OFF 
		: KEV_DL_LINK_ON;
	}
    } else {
	bond_set_static_mode(ifb);
	event_code = (ifb->ifb_distributing_count == 0) 
	    ? KEV_DL_LINK_OFF 
	    : KEV_DL_LINK_ON;
    }
    ifb->ifb_last_link_event = event_code;

 signal_done:
    ifbond_signal(ifb, "bond_set_mode");
    bond_unlock();
    ifbond_release(ifb);

    if (event_code != 0) {
	interface_link_event(ifp, event_code);
    }
    return (error);
}

static int
bond_get_status(ifbond_ref ifb, struct if_bond_req * ibr_p, user_addr_t datap)
{
    int				count;
    user_addr_t			dst;
    int				error = 0;
    struct if_bond_status_req *	ibsr;
    struct if_bond_status	ibs;
    bondport_ref		port;

    ibsr = &(ibr_p->ibr_ibru.ibru_status);
    if (ibsr->ibsr_version != IF_BOND_STATUS_REQ_VERSION) {
	return (EINVAL);
    }
    ibsr->ibsr_key = ifb->ifb_key;
    ibsr->ibsr_mode = ifb->ifb_mode;
    ibsr->ibsr_total = ifb->ifb_port_count;
    dst = proc_is64bit(current_proc())
	? ibsr->ibsr_ibsru.ibsru_buffer64
	: CAST_USER_ADDR_T(ibsr->ibsr_ibsru.ibsru_buffer);
    if (dst == USER_ADDR_NULL) {
	/* just want to know how many there are */
	goto done;
    }
    if (ibsr->ibsr_count < 0) {
	return (EINVAL);
    }
    count = (ifb->ifb_port_count < ibsr->ibsr_count) 
	? ifb->ifb_port_count : ibsr->ibsr_count;
    TAILQ_FOREACH(port, &ifb->ifb_port_list, po_port_list) {
	struct if_bond_partner_state * 	ibps_p;
	partner_state_ref		ps;

	if (count == 0) {
	    break;
	}
	bzero(&ibs, sizeof(ibs));
	strlcpy(ibs.ibs_if_name, port->po_name, sizeof(ibs.ibs_if_name));
	ibs.ibs_port_priority = port->po_priority;
	if (ifb->ifb_mode == IF_BOND_MODE_LACP) {
	    ibs.ibs_state = port->po_actor_state;
	    ibs.ibs_selected_state = port->po_selected;
	    ps = &port->po_partner_state;
	    ibps_p = &ibs.ibs_partner_state;
	    ibps_p->ibps_system = ps->ps_lag_info.li_system;
	    ibps_p->ibps_system_priority = ps->ps_lag_info.li_system_priority;
	    ibps_p->ibps_key = ps->ps_lag_info.li_key;
	    ibps_p->ibps_port = ps->ps_port;
	    ibps_p->ibps_port_priority = ps->ps_port_priority;
	    ibps_p->ibps_state = ps->ps_state;
	}
	else {
	    /* fake the selected information */
	    ibs.ibs_selected_state = bondport_flags_distributing(port)
		? SelectedState_SELECTED : SelectedState_UNSELECTED;
	}
	error = copyout(&ibs, dst, sizeof(ibs));
	if (error != 0) {
	    break;
	}
	dst += sizeof(ibs);
	count--;
    }

 done:
    if (error == 0) {
	error = copyout(ibr_p, datap, sizeof(*ibr_p));
    }
    else {
	(void)copyout(ibr_p, datap, sizeof(*ibr_p));
    }
    return (error);
}

static int
bond_set_promisc(__unused struct ifnet *ifp)
{
    int 		error = 0;
    return (error);
}

static void
bond_get_mtu_values(ifbond_ref ifb, int * ret_min, int * ret_max)
{
    int				mtu_min = 0;
    int				mtu_max = 0;
    bondport_ref		p;

    if (TAILQ_FIRST(&ifb->ifb_port_list) != NULL) {
	mtu_min = IF_MINMTU;
    }
    TAILQ_FOREACH(p, &ifb->ifb_port_list, po_port_list) {
	struct ifdevmtu *	devmtu_p = &p->po_devmtu;

	if (devmtu_p->ifdm_min > mtu_min) {
	    mtu_min = devmtu_p->ifdm_min;
	}
	if (mtu_max == 0 || devmtu_p->ifdm_max < mtu_max) {
	    mtu_max = devmtu_p->ifdm_max;
	}
    }
    *ret_min = mtu_min;
    *ret_max = mtu_max;
    return;
}

static int
bond_set_mtu_on_ports(ifbond_ref ifb, int mtu)
{
    int				error = 0;
    bondport_ref		p;

    TAILQ_FOREACH(p, &ifb->ifb_port_list, po_port_list) {
	error = siocsifmtu(p->po_ifp, mtu);
	if (error != 0) {
	    printf("if_bond(%s): SIOCSIFMTU %s failed, %d\n",
		   ifb->ifb_name, bondport_get_name(p), error);
	    break;
	}
    }
    return (error);
}

static int
bond_set_mtu(struct ifnet * ifp, int mtu, int isdevmtu)
{
    int			error = 0;
    ifbond_ref		ifb;
    int			mtu_min;
    int			mtu_max;
    int			new_max;
    int			old_max;

    bond_lock();
    ifb = (ifbond_ref)ifnet_softc(ifp);
    if (ifb == NULL || ifbond_flags_if_detaching(ifb)) {
	error = (ifb == NULL) ? EOPNOTSUPP : EBUSY;
	goto done;
    }
    ifbond_retain(ifb);
    ifbond_wait(ifb, "bond_set_mtu");

    /* check again */
    if (ifnet_softc(ifp) == NULL || ifbond_flags_if_detaching(ifb)) {
	error = EBUSY;
	goto signal_done;
    }
    bond_get_mtu_values(ifb, &mtu_min, &mtu_max);
    if (mtu > mtu_max) {
	error = EINVAL;
	goto signal_done;
    }
    if (mtu < mtu_min && (isdevmtu == 0 || mtu != 0)) {
	/* allow SIOCSIFALTMTU to set the mtu to 0 */
	error = EINVAL;
	goto signal_done;
    }
    if (isdevmtu) {
	new_max = (mtu > (int)ifnet_mtu(ifp)) ? mtu : (int)ifnet_mtu(ifp);
    }
    else {
	new_max = (mtu > ifb->ifb_altmtu) ? mtu : ifb->ifb_altmtu;
    }
    old_max = ((int)ifnet_mtu(ifp) > ifb->ifb_altmtu) 
	? (int)ifnet_mtu(ifp) : ifb->ifb_altmtu;
    if (new_max != old_max) {
	/* we can safely walk the list of port without the lock held */
	bond_unlock();
	error = bond_set_mtu_on_ports(ifb, new_max);
	if (error != 0) {
	    /* try our best to back out of it */
	    (void)bond_set_mtu_on_ports(ifb, old_max);
	}
	bond_lock();
    }
    if (error == 0) {
	if (isdevmtu) {
	    ifb->ifb_altmtu = mtu;
	}
	else {
		ifnet_set_mtu(ifp, mtu);
	}
    }

 signal_done:
    ifbond_signal(ifb, "bond_set_mtu");
    ifbond_release(ifb);
    
 done:
    bond_unlock();
    return (error);
}

static int
bond_ioctl(struct ifnet *ifp, u_long cmd, void * data)
{
    int 		error = 0;
    struct if_bond_req	ibr;
    struct ifaddr *	ifa;
    ifbond_ref		ifb;
    struct ifreq *	ifr;
    struct ifmediareq	*ifmr;
    struct ifnet *	port_ifp = NULL;
    user_addr_t		user_addr;

    if (ifnet_type(ifp) != IFT_IEEE8023ADLAG) {
	return (EOPNOTSUPP);
    }
    ifr = (struct ifreq *)data;
    ifa = (struct ifaddr *)data;

    switch (cmd) {
    case SIOCSIFADDR:
	ifnet_set_flags(ifp, IFF_UP, IFF_UP);
	break;

    case SIOCGIFMEDIA32:
    case SIOCGIFMEDIA64:
	bond_lock();
	ifb = (ifbond_ref)ifnet_softc(ifp);
	if (ifb == NULL || ifbond_flags_if_detaching(ifb)) {
	    bond_unlock();
	    return (ifb == NULL ? EOPNOTSUPP : EBUSY);
	}
	ifmr = (struct ifmediareq *)data;
	ifmr->ifm_current = IFM_ETHER;
	ifmr->ifm_mask = 0;
	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;
	ifmr->ifm_count = 1;
	if (ifb->ifb_mode == IF_BOND_MODE_LACP) {
	    if (ifb->ifb_active_lag != NULL) {
		ifmr->ifm_active = ifb->ifb_active_lag->lag_active_media;
		ifmr->ifm_status |= IFM_ACTIVE;
	    }
	}
	else if (ifb->ifb_distributing_count > 0) {
	    ifmr->ifm_active
		= ifb->ifb_distributing_array[0]->po_media_info.mi_active;
	    ifmr->ifm_status |= IFM_ACTIVE;
	}
	bond_unlock();
	user_addr = (cmd == SIOCGIFMEDIA64) ?
	    ((struct ifmediareq64 *)ifmr)->ifmu_ulist :
	    CAST_USER_ADDR_T(((struct ifmediareq32 *)ifmr)->ifmu_ulist);
	if (user_addr != USER_ADDR_NULL) {
	    error = copyout(&ifmr->ifm_current,
			    user_addr,
			    sizeof(int));
	}
	break;

    case SIOCSIFMEDIA:
	/* XXX send the SIFMEDIA to all children?  Or force autoselect? */
	error = EINVAL;
	break;

    case SIOCGIFDEVMTU:
	bond_lock();
	ifb = (ifbond_ref)ifnet_softc(ifp);
	if (ifb == NULL || ifbond_flags_if_detaching(ifb)) {
	    bond_unlock();
	    error = (ifb == NULL) ? EOPNOTSUPP : EBUSY;
	    break;
	}
	ifr->ifr_devmtu.ifdm_current = bond_device_mtu(ifp, ifb);
	bond_get_mtu_values(ifb, &ifr->ifr_devmtu.ifdm_min,
			    &ifr->ifr_devmtu.ifdm_max);
	bond_unlock();
	break;

    case SIOCGIFALTMTU:
	bond_lock();
	ifb = (ifbond_ref)ifnet_softc(ifp);
	if (ifb == NULL || ifbond_flags_if_detaching(ifb)) {
	    bond_unlock();
	    error = (ifb == NULL) ? EOPNOTSUPP : EBUSY;
	    break;
	}
	ifr->ifr_mtu = ifb->ifb_altmtu;
	bond_unlock();
	break;

    case SIOCSIFALTMTU:
	error = bond_set_mtu(ifp, ifr->ifr_mtu, 1);
	break;

    case SIOCSIFMTU:
	error = bond_set_mtu(ifp, ifr->ifr_mtu, 0);
	break;

    case SIOCSIFBOND:
	user_addr = proc_is64bit(current_proc())
	    ? ifr->ifr_data64 : CAST_USER_ADDR_T(ifr->ifr_data);
	error = copyin(user_addr, &ibr, sizeof(ibr));
	if (error) {
	    break;
	}
	switch (ibr.ibr_op) {
	case IF_BOND_OP_ADD_INTERFACE:
	case IF_BOND_OP_REMOVE_INTERFACE:
	    port_ifp = ifunit(ibr.ibr_ibru.ibru_if_name);
	    if (port_ifp == NULL) {
		error = ENXIO;
		break;
	    }
	    if (ifnet_type(port_ifp) != IFT_ETHER) {
		error = EPROTONOSUPPORT;
		break;
	    }
	    break;
	case IF_BOND_OP_SET_VERBOSE:
	case IF_BOND_OP_SET_MODE:
	    break;
	default:
	    error = EOPNOTSUPP;
	    break;
	}
	if (error != 0) {
	    break;
	}
	switch (ibr.ibr_op) {
	case IF_BOND_OP_ADD_INTERFACE:
	    error = bond_add_interface(ifp, port_ifp);
	    break;
	case IF_BOND_OP_REMOVE_INTERFACE:
	    bond_lock();
	    ifb = (ifbond_ref)ifnet_softc(ifp);
	    if (ifb == NULL || ifbond_flags_if_detaching(ifb)) {
		bond_unlock();
		return (ifb == NULL ? EOPNOTSUPP : EBUSY);
	    }
	    error = bond_remove_interface(ifb, port_ifp);
	    bond_unlock();
	    break;
	case IF_BOND_OP_SET_VERBOSE:
	    bond_lock();
	    if (g_bond == NULL) {
		bond_unlock();
		error = ENXIO;
		break;
	    }
	    g_bond->verbose = ibr.ibr_ibru.ibru_int_val;
	    bond_unlock();
	    break;
	case IF_BOND_OP_SET_MODE:
	    switch (ibr.ibr_ibru.ibru_int_val) {
	    case IF_BOND_MODE_LACP:
	    case IF_BOND_MODE_STATIC:
		break;
	    default:
		error = EINVAL;
		break;
	    }
	    if (error != 0) {
		break;
	    }
	    error = bond_set_mode(ifp, ibr.ibr_ibru.ibru_int_val);
	    break;
	}
	break; /* SIOCSIFBOND */
		
    case SIOCGIFBOND:
	user_addr = proc_is64bit(current_proc())
	    ? ifr->ifr_data64 : CAST_USER_ADDR_T(ifr->ifr_data);
	error = copyin(user_addr, &ibr, sizeof(ibr));
	if (error) {
	    break;
	}
	switch (ibr.ibr_op) {
	case IF_BOND_OP_GET_STATUS:
	    break;
	default:
	    error = EOPNOTSUPP;
	    break;
	}
	if (error != 0) {
	    break;
	}
	bond_lock();
	ifb = (ifbond_ref)ifnet_softc(ifp);
	if (ifb == NULL || ifbond_flags_if_detaching(ifb)) {
	    bond_unlock();
	    return (ifb == NULL ? EOPNOTSUPP : EBUSY);
	}
	switch (ibr.ibr_op) {
	case IF_BOND_OP_GET_STATUS:
	    error = bond_get_status(ifb, &ibr, user_addr);
	    break;
	}
	bond_unlock();
	break; /* SIOCGIFBOND */
		
    case SIOCSIFLLADDR:
	error = EOPNOTSUPP;
	break;

    case SIOCSIFFLAGS:
	/* enable/disable promiscuous mode */
	bond_lock();
	error = bond_set_promisc(ifp);
	bond_unlock();
	break;

    case SIOCADDMULTI:
    case SIOCDELMULTI:
	error = bond_setmulti(ifp);
	break;
    default:
	error = EOPNOTSUPP;
    }
    return error;
}

static void 
bond_if_free(struct ifnet * ifp)
{
    ifbond_ref 	ifb;

    if (ifp == NULL) {
	return;
    }
    bond_lock();
    ifb = (ifbond_ref)ifnet_softc(ifp);
    if (ifb == NULL) {
	bond_unlock();
	return;
    }
    ifbond_release(ifb);
    bond_unlock();
    ifnet_release(ifp);
    return;
}

static void
bond_handle_event(struct ifnet * port_ifp, int event_code)
{
    struct ifnet *	bond_ifp = NULL;
    ifbond_ref		ifb;
    int			old_distributing_count;
    bondport_ref	p;
    struct media_info	media_info = { 0, 0};

    switch (event_code) {
    case KEV_DL_IF_DETACHED:
	break;
    case KEV_DL_LINK_OFF:
    case KEV_DL_LINK_ON:
	media_info = interface_media_info(port_ifp);
	break;
    default:
	return;
    }
    bond_lock();
    p = bond_lookup_port(port_ifp);
    if (p == NULL) {
	bond_unlock();
	return;
    }
    ifb = p->po_bond;
    old_distributing_count = ifb->ifb_distributing_count;
    switch (event_code) {
    case KEV_DL_IF_DETACHED:
	bond_remove_interface(ifb, p->po_ifp);
	break;
    case KEV_DL_LINK_OFF:
    case KEV_DL_LINK_ON:
	p->po_media_info = media_info;
	if (p->po_enabled) {
	    bondport_link_status_changed(p);
	}
	break;
    }
    /* generate a link-event */
    if (ifb->ifb_mode == IF_BOND_MODE_LACP) {
	if (ifbond_selection(ifb)) {
	    event_code = (ifb->ifb_active_lag == NULL) 
		? KEV_DL_LINK_OFF 
		: KEV_DL_LINK_ON;
	    /* XXX need to take a reference on bond_ifp */
	    bond_ifp = ifb->ifb_ifp;
	    ifb->ifb_last_link_event = event_code;
	}
	else {
	    event_code = (ifb->ifb_active_lag == NULL) 
		? KEV_DL_LINK_OFF 
		: KEV_DL_LINK_ON;
	    if (event_code != ifb->ifb_last_link_event) {
		if (g_bond->verbose) {
		    timestamp_printf("%s: (event) generating LINK event\n",
				     ifb->ifb_name);
		}
		bond_ifp = ifb->ifb_ifp;
		ifb->ifb_last_link_event = event_code;
	    }
	}
    }
    else {
	/*
	 * if the distributing array membership changed from 0 <-> !0
	 * generate a link event
	 */
	if (old_distributing_count == 0 
	    && ifb->ifb_distributing_count != 0) {
	    event_code = KEV_DL_LINK_ON;
	}
	else if (old_distributing_count != 0 
		 && ifb->ifb_distributing_count == 0) {
	    event_code = KEV_DL_LINK_OFF;
	}
	if (event_code != 0 && event_code != ifb->ifb_last_link_event) {
	    bond_ifp = ifb->ifb_ifp;
	    ifb->ifb_last_link_event = event_code;
	}
    }

    bond_unlock();
    if (bond_ifp != NULL) {
	interface_link_event(bond_ifp, event_code);
    }
    return;
}

static void
bond_event(struct ifnet * port_ifp, __unused protocol_family_t protocol,
	   const struct kev_msg * event)
{
    int		event_code;

    if (event->vendor_code != KEV_VENDOR_APPLE 
	|| event->kev_class != KEV_NETWORK_CLASS 
	|| event->kev_subclass != KEV_DL_SUBCLASS) {
	return;
    }
    event_code = event->event_code;
    switch (event_code) {
    case KEV_DL_LINK_OFF:
    case KEV_DL_LINK_ON:
	/* we only care about link status changes */
	bond_handle_event(port_ifp, event_code);
	break;
    default:
	break;
    }
    return;
}

static errno_t
bond_detached(ifnet_t port_ifp, __unused protocol_family_t protocol)
{
    bond_handle_event(port_ifp, KEV_DL_IF_DETACHED);
    return (0);
}

static void
interface_link_event(struct ifnet * ifp, u_int32_t event_code)
{
    struct {
	struct kern_event_msg	header;
	u_int32_t			unit;
	char			if_name[IFNAMSIZ];
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

/*
 * Function: bond_attach_protocol
 * Purpose:
 *   Attach a DLIL protocol to the interface.
 *
 *   The ethernet demux special cases to always return PF_BOND if the 
 *   interface is bonded.  That means we receive all traffic from that
 *   interface without passing any of the traffic to any other attached
 *   protocol.
 */
static int
bond_attach_protocol(struct ifnet *ifp)
{
    int								error;
    struct ifnet_attach_proto_param	reg;
	
    bzero(&reg, sizeof(reg));
    reg.input = bond_input;
    reg.event = bond_event;
    reg.detached = bond_detached;
	
    error = ifnet_attach_protocol(ifp, PF_BOND, &reg);
    if (error) {
	printf("bond over %s%d: ifnet_attach_protocol failed, %d\n",
	       ifnet_name(ifp), ifnet_unit(ifp), error);
    }
    return (error);
}

/*
 * Function: bond_detach_protocol
 * Purpose:
 *   Detach our DLIL protocol from an interface
 */
static int
bond_detach_protocol(struct ifnet *ifp)
{
    int         error;

    error = ifnet_detach_protocol(ifp, PF_BOND);
    if (error) {
	printf("bond over %s%d: ifnet_detach_protocol failed, %d\n",
	       ifnet_name(ifp), ifnet_unit(ifp), error);
    }
    return (error);
}

/*
 * DLIL interface family functions
 */
extern int ether_attach_inet(ifnet_t ifp, protocol_family_t protocol_family);
extern void ether_detach_inet(ifnet_t ifp, protocol_family_t protocol_family);
extern int ether_attach_inet6(ifnet_t ifp, protocol_family_t protocol_family);
extern void ether_detach_inet6(ifnet_t ifp, protocol_family_t protocol_family);
extern int ether_attach_at(ifnet_t ifp, protocol_family_t protocol_family);
extern void ether_detach_at(ifnet_t ifp, protocol_family_t protocol_family);

__private_extern__ int
bond_family_init(void)
{
    int error=0;

    error = proto_register_plumber(PF_INET, APPLE_IF_FAM_BOND, 
				  ether_attach_inet, 
				  ether_detach_inet);
    if (error != 0) {
	printf("bond: proto_register_plumber failed for AF_INET error=%d\n",
	       error);
	goto done;
    }
#if INET6
    error = proto_register_plumber(PF_INET6, APPLE_IF_FAM_BOND, 
				  ether_attach_inet6, 
				  ether_detach_inet6);
    if (error != 0) {
	printf("bond: proto_register_plumber failed for AF_INET6 error=%d\n",
	       error);
	goto done;
    }
#endif
    error = bond_clone_attach();
    if (error != 0) {
        printf("bond: proto_register_plumber failed bond_clone_attach error=%d\n",
               error);
        goto done;
    }

 done:
    return (error);
}
/**
 **
 ** LACP routines:
 **
 **/

/**
 ** LACP ifbond_list routines
 **/
static bondport_ref
ifbond_list_find_moved_port(bondport_ref rx_port, 
			    const lacp_actor_partner_tlv_ref atlv)
{
    ifbond_ref		bond;
    bondport_ref	p;
    partner_state_ref	ps;
    LAG_info_ref	ps_li;

    TAILQ_FOREACH(bond, &g_bond->ifbond_list, ifb_bond_list) {
	TAILQ_FOREACH(p, &bond->ifb_port_list, po_port_list) {

	    if (rx_port == p) {
		/* no point in comparing against ourselves */
		continue;
	    }
	    if (p->po_receive_state != ReceiveState_PORT_DISABLED) {
		/* it's not clear that we should be checking this */
		continue;
	    }
	    ps = &p->po_partner_state;
	    if (lacp_actor_partner_state_defaulted(ps->ps_state)) {
		continue;
	    }
	    ps_li = &ps->ps_lag_info;
	    if (ps->ps_port == lacp_actor_partner_tlv_get_port(atlv)
		&& bcmp(&ps_li->li_system, atlv->lap_system,
			sizeof(ps_li->li_system)) == 0) {
		if (g_bond->verbose) {
		    timestamp_printf("System " EA_FORMAT 
				     " Port 0x%x moved from %s to %s\n",
				     EA_LIST(&ps_li->li_system), ps->ps_port, 
				     bondport_get_name(p), 
				     bondport_get_name(rx_port));
		}
		return (p);
	    }
	}
    }
    return (NULL);
}

/**
 ** LACP ifbond, LAG routines
 **/

static int
ifbond_selection(ifbond_ref bond)
{
    int			all_ports_ready = 0;
    int			active_media = 0;
    LAG_ref		lag = NULL;
    int			lag_changed = 0;
    bondport_ref	p;
    int			port_speed = 0;
    
    lag = ifbond_find_best_LAG(bond, &active_media);
    if (lag != bond->ifb_active_lag) {
	if (bond->ifb_active_lag != NULL) {
	    ifbond_deactivate_LAG(bond, bond->ifb_active_lag);
	    bond->ifb_active_lag = NULL;
	}
	bond->ifb_active_lag = lag;
	if (lag != NULL) {
	    ifbond_activate_LAG(bond, lag, active_media);
	}
	lag_changed = 1;
    }
    else if (lag != NULL) {
	if (lag->lag_active_media != active_media) {
	    if (g_bond->verbose) {
		timestamp_printf("LAG PORT SPEED CHANGED from %d to %d\n",
				 link_speed(lag->lag_active_media), 
				 link_speed(active_media));
	    }
	    ifbond_deactivate_LAG(bond, lag);
	    ifbond_activate_LAG(bond, lag, active_media);
	    lag_changed = 1;
	}
    }
    if (lag != NULL) {
	port_speed = link_speed(active_media);
	all_ports_ready = ifbond_all_ports_ready(bond);
    }
    TAILQ_FOREACH(p, &bond->ifb_port_list, po_port_list) {
	if (lag != NULL && p->po_lag == lag
	    && media_speed(&p->po_media_info) == port_speed
	    && (p->po_mux_state == MuxState_DETACHED
		|| p->po_selected == SelectedState_SELECTED
		|| p->po_selected == SelectedState_STANDBY)
	    && bondport_aggregatable(p)) {
	    if (bond->ifb_max_active > 0) {
		if (lag->lag_selected_port_count < bond->ifb_max_active) {
		    if (p->po_selected == SelectedState_STANDBY
			|| p->po_selected == SelectedState_UNSELECTED) {
			bondport_set_selected(p, SelectedState_SELECTED);
		    }
		}
		else if (p->po_selected == SelectedState_UNSELECTED) {
		    bondport_set_selected(p, SelectedState_STANDBY);
		}
	    }
	    else {
		bondport_set_selected(p, SelectedState_SELECTED);
	    }
	}
	if (bondport_flags_selected_changed(p)) {
	    bondport_flags_clear_selected_changed(p);
	    bondport_mux_machine(p, LAEventSelectedChange, NULL);
	}
	if (all_ports_ready
	    && bondport_flags_ready(p)
	    && p->po_mux_state == MuxState_WAITING) {
	    bondport_mux_machine(p, LAEventReady, NULL);
	}
	bondport_transmit_machine(p, LAEventStart, NULL);
    }
    return (lag_changed);
}

static LAG_ref
ifbond_find_best_LAG(ifbond_ref bond, int * active_media)
{
    int			best_active = 0;
    LAG_ref		best_lag = NULL;
    int			best_count = 0;
    int			best_speed = 0;
    LAG_ref		lag;

    if (bond->ifb_active_lag != NULL) {
	best_lag = bond->ifb_active_lag;
	best_count = LAG_get_aggregatable_port_count(best_lag, &best_active);
	if (bond->ifb_max_active > 0
	    && best_count > bond->ifb_max_active) {
	    best_count = bond->ifb_max_active;
	}
	best_speed = link_speed(best_active);
    }
    TAILQ_FOREACH(lag, &bond->ifb_lag_list, lag_list) {
	int	active;
	int	count;
	int	speed;

	if (lag == bond->ifb_active_lag) {
	    /* we've already computed it */
	    continue;
	}
	count = LAG_get_aggregatable_port_count(lag, &active);
	if (count == 0) {
	    continue;
	}
	if (bond->ifb_max_active > 0
	    && count > bond->ifb_max_active) {
	    /* if there's a limit, don't count extra links */
	    count = bond->ifb_max_active;
	}
	speed = link_speed(active);
	if ((count * speed) > (best_count * best_speed)) {
	    best_count = count;
	    best_speed = speed;
	    best_active = active;
	    best_lag = lag;
	}
    }
    if (best_count == 0) {
	return (NULL);
    }
    *active_media = best_active;
    return (best_lag);
}

static void
ifbond_deactivate_LAG(__unused ifbond_ref bond, LAG_ref lag)
{
    bondport_ref	p;

    TAILQ_FOREACH(p, &lag->lag_port_list, po_lag_port_list) {
	bondport_set_selected(p, SelectedState_UNSELECTED);
    }
    return;
}

static void
ifbond_activate_LAG(ifbond_ref bond, LAG_ref lag, int active_media)
{
    int			need = 0;
    bondport_ref	p;

    if (bond->ifb_max_active > 0) {
	need = bond->ifb_max_active;
    }
    lag->lag_active_media = active_media;
    TAILQ_FOREACH(p, &lag->lag_port_list, po_lag_port_list) {
	if (bondport_aggregatable(p) == 0) {
	    bondport_set_selected(p, SelectedState_UNSELECTED);
	}
	else if (media_speed(&p->po_media_info) != link_speed(active_media)) {
	    bondport_set_selected(p, SelectedState_UNSELECTED);
	}
	else if (p->po_mux_state == MuxState_DETACHED) {
	    if (bond->ifb_max_active > 0) {
		if (need > 0) {
		    bondport_set_selected(p, SelectedState_SELECTED);
		    need--;
		}
		else {
		    bondport_set_selected(p, SelectedState_STANDBY);
		}
	    }
	    else {
		bondport_set_selected(p, SelectedState_SELECTED);
	    }
	}
	else {
	    bondport_set_selected(p, SelectedState_UNSELECTED);
	}
    }
    return;
}

#if 0
static void
ifbond_set_max_active(ifbond_ref bond, int max_active)
{
    LAG_ref	lag = bond->ifb_active_lag;

    bond->ifb_max_active = max_active;
    if (bond->ifb_max_active <= 0 || lag == NULL) {
	return;
    }
    if (lag->lag_selected_port_count > bond->ifb_max_active) {
	bondport_ref	p;
	int			remove_count;

	remove_count = lag->lag_selected_port_count - bond->ifb_max_active;
	TAILQ_FOREACH(p, &lag->lag_port_list, po_lag_port_list) {
	    if (p->po_selected == SelectedState_SELECTED) {
		bondport_set_selected(p, SelectedState_UNSELECTED);
		remove_count--;
		if (remove_count == 0) {
		    break;
		}
	    }
	}
    }
    return;
}
#endif

static int
ifbond_all_ports_ready(ifbond_ref bond)
{
    int			ready = 0;
    bondport_ref	p;

    if (bond->ifb_active_lag == NULL) {
	return (0);
    }
    TAILQ_FOREACH(p, &bond->ifb_active_lag->lag_port_list, po_lag_port_list) {
	if (p->po_mux_state == MuxState_WAITING
	    && p->po_selected == SelectedState_SELECTED) {
	    if (bondport_flags_ready(p) == 0) {
		return (0);
	    }
	}
	/* note that there was at least one ready port */
	ready = 1;
    }
    return (ready);
}

static int
ifbond_all_ports_attached(ifbond_ref bond, bondport_ref this_port)
{
    bondport_ref	p;

    TAILQ_FOREACH(p, &bond->ifb_port_list, po_port_list) {
	if (this_port == p) {
	    continue;
	}
	if (bondport_flags_mux_attached(p) == 0) {
	    return (0);
	}
    }
    return (1);
}

static LAG_ref
ifbond_get_LAG_matching_port(ifbond_ref bond, bondport_ref p)
{
    LAG_ref	lag;

    TAILQ_FOREACH(lag, &bond->ifb_lag_list, lag_list) {
	if (bcmp(&lag->lag_info, &p->po_partner_state.ps_lag_info,
		 sizeof(lag->lag_info)) == 0) {
	    return (lag);
	}
    }
    return (NULL);
}

static int
LAG_get_aggregatable_port_count(LAG_ref lag, int * active_media)
{
    int			active;
    int 		count;
    bondport_ref	p;
    int			speed;

    active = 0;
    count = 0;
    speed = 0;
    TAILQ_FOREACH(p, &lag->lag_port_list, po_lag_port_list) {
	if (bondport_aggregatable(p)) {
	    int this_speed;

	    this_speed = media_speed(&p->po_media_info);
	    if (this_speed == 0) {
		continue;
	    }
	    if (this_speed > speed) {
		active = p->po_media_info.mi_active;
		speed = this_speed;
		count = 1;
	    }
	    else if (this_speed == speed) {
		count++;
	    }
	}
    }
    *active_media = active;
    return (count);
}


/**
 ** LACP bondport routines
 **/
static void
bondport_link_status_changed(bondport_ref p)
{
    ifbond_ref	bond = p->po_bond;

    if (g_bond->verbose) {
	if (media_active(&p->po_media_info)) {
	    timestamp_printf("[%s] Link UP %d Mbit/s %s duplex\n", 
			     bondport_get_name(p),
			     media_speed(&p->po_media_info),
			     media_full_duplex(&p->po_media_info) 
			     ? "full" : "half");
	}
	else {
	    timestamp_printf("[%s] Link DOWN\n", bondport_get_name(p));
	}
    }
    if (bond->ifb_mode == IF_BOND_MODE_LACP) {
	if (media_active(&p->po_media_info)
	    && bond->ifb_active_lag != NULL
	    && p->po_lag == bond->ifb_active_lag
	    && p->po_selected != SelectedState_UNSELECTED) {
	    if (media_speed(&p->po_media_info) != p->po_lag->lag_active_media) {
		if (g_bond->verbose) {
		    timestamp_printf("[%s] Port speed %d differs from LAG %d\n",
				     bondport_get_name(p),
				     media_speed(&p->po_media_info),
				     link_speed(p->po_lag->lag_active_media));
		}
		bondport_set_selected(p, SelectedState_UNSELECTED);
	    }
	}
	bondport_receive_machine(p, LAEventMediaChange, NULL);
	bondport_mux_machine(p, LAEventMediaChange, NULL);
	bondport_periodic_transmit_machine(p, LAEventMediaChange, NULL);
    }
    else {
	if (media_active(&p->po_media_info)) {
	    bondport_enable_distributing(p);
	}
	else {
	    bondport_disable_distributing(p);
	}
    }
    return;
}

static int
bondport_aggregatable(bondport_ref p)
{
    partner_state_ref 	ps = &p->po_partner_state;

    if (lacp_actor_partner_state_aggregatable(p->po_actor_state) == 0
	|| lacp_actor_partner_state_aggregatable(ps->ps_state) == 0) {
	/* we and/or our partner are individual */
	return (0);
    }
    if (p->po_lag == NULL) {
	return (0);
    }
    switch (p->po_receive_state) {
    default:
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Port is not selectable\n", 
			     bondport_get_name(p));
	}
	return (0);
    case ReceiveState_CURRENT:
    case ReceiveState_EXPIRED:
	break;
    }
    return (1);
}

static int
bondport_matches_LAG(bondport_ref p, LAG_ref lag)
{
    LAG_info_ref	lag_li;
    partner_state_ref	ps;
    LAG_info_ref	ps_li;

    ps = &p->po_partner_state;
    ps_li = &ps->ps_lag_info;
    lag_li = &lag->lag_info;
    if (ps_li->li_system_priority == lag_li->li_system_priority
	&& ps_li->li_key == lag_li->li_key
	&& (bcmp(&ps_li->li_system, &lag_li->li_system, 
		 sizeof(lag_li->li_system))
	    == 0)) {
	return (1);
    }
    return (0);
}

static int
bondport_remove_from_LAG(bondport_ref p)
{
    int		active_lag = 0;
    ifbond_ref	bond = p->po_bond;
    LAG_ref	lag = p->po_lag;

    if (lag == NULL) {
	return (0);
    }
    TAILQ_REMOVE(&lag->lag_port_list, p, po_lag_port_list);
    if (g_bond->verbose) {
	timestamp_printf("[%s] Removed from LAG (0x%04x," EA_FORMAT 
			 ",0x%04x)\n",
			 bondport_get_name(p),
			 lag->lag_info.li_system_priority,
			 EA_LIST(&lag->lag_info.li_system),
			 lag->lag_info.li_key);
    }
    p->po_lag = NULL;
    lag->lag_port_count--;
    if (lag->lag_port_count > 0) {
	return (bond->ifb_active_lag == lag);
    }
    if (g_bond->verbose) {
	timestamp_printf("Key 0x%04x: LAG Released (%04x," EA_FORMAT 
			 ",0x%04x)\n",
			 bond->ifb_key,
			 lag->lag_info.li_system_priority,
			 EA_LIST(&lag->lag_info.li_system),
			 lag->lag_info.li_key);
    }
    TAILQ_REMOVE(&bond->ifb_lag_list, lag, lag_list);
    if (bond->ifb_active_lag == lag) {
	bond->ifb_active_lag = NULL;
	active_lag = 1;
    }
    FREE(lag, M_BOND);
    return (active_lag);
}

static void
bondport_add_to_LAG(bondport_ref p, LAG_ref lag)
{
    TAILQ_INSERT_TAIL(&lag->lag_port_list, p, po_lag_port_list);
    p->po_lag = lag;
    lag->lag_port_count++;
    if (g_bond->verbose) {
	timestamp_printf("[%s] Added to LAG (0x%04x," EA_FORMAT "0x%04x)\n",
			 bondport_get_name(p),
			 lag->lag_info.li_system_priority,
			 EA_LIST(&lag->lag_info.li_system),
			 lag->lag_info.li_key);
    }
    return;
}

static void
bondport_assign_to_LAG(bondport_ref p)
{
    ifbond_ref	bond = p->po_bond;
    LAG_ref	lag;

    if (lacp_actor_partner_state_defaulted(p->po_actor_state)) {
	bondport_remove_from_LAG(p);
	return;
    }
    lag = p->po_lag;
    if (lag != NULL) {
	if (bondport_matches_LAG(p, lag)) {
	    /* still OK */
	    return;
	}
	bondport_remove_from_LAG(p);
    }
    lag = ifbond_get_LAG_matching_port(bond, p);
    if (lag != NULL) {
	bondport_add_to_LAG(p, lag);
	return;
    }
    lag = (LAG_ref)_MALLOC(sizeof(*lag), M_BOND, M_WAITOK);
    TAILQ_INIT(&lag->lag_port_list);
    lag->lag_port_count = 0;
    lag->lag_selected_port_count = 0;
    lag->lag_info = p->po_partner_state.ps_lag_info;
    TAILQ_INSERT_TAIL(&bond->ifb_lag_list, lag, lag_list);
    if (g_bond->verbose) {
	timestamp_printf("Key 0x%04x: LAG Created (0x%04x," EA_FORMAT 
			 ",0x%04x)\n",
			 bond->ifb_key,
			 lag->lag_info.li_system_priority,
			 EA_LIST(&lag->lag_info.li_system),
			 lag->lag_info.li_key);
    }
    bondport_add_to_LAG(p, lag);
    return;
}

static void
bondport_receive_lacpdu(bondport_ref p, lacpdu_ref in_lacpdu_p)
{
    bondport_ref		moved_port;

    moved_port
	= ifbond_list_find_moved_port(p, (const lacp_actor_partner_tlv_ref)
				      &in_lacpdu_p->la_actor_tlv);
    if (moved_port != NULL) {
	bondport_receive_machine(moved_port, LAEventPortMoved, NULL);
    }
    bondport_receive_machine(p, LAEventPacket, in_lacpdu_p);
    bondport_mux_machine(p, LAEventPacket, in_lacpdu_p);
    bondport_periodic_transmit_machine(p, LAEventPacket, in_lacpdu_p);
    return;
}

static void 
bondport_set_selected(bondport_ref p, SelectedState s)
{
    if (s != p->po_selected) {
	ifbond_ref	bond = p->po_bond;
	LAG_ref		lag = p->po_lag;

	bondport_flags_set_selected_changed(p);
	if (lag != NULL && bond->ifb_active_lag == lag) {
	    if (p->po_selected == SelectedState_SELECTED) {
		lag->lag_selected_port_count--;
	    }
	    else if (s == SelectedState_SELECTED) {
		lag->lag_selected_port_count++;
	    }
	    if (g_bond->verbose) {
		timestamp_printf("[%s] SetSelected: %s (was %s)\n",
				 bondport_get_name(p), 
				 SelectedStateString(s),
				 SelectedStateString(p->po_selected));
	    }
	}
    }
    p->po_selected = s;
    return;
}

/**
 ** Receive machine
 **/

static void
bondport_UpdateDefaultSelected(bondport_ref p)
{
    bondport_set_selected(p, SelectedState_UNSELECTED);
    return;
}

static void
bondport_RecordDefault(bondport_ref p)
{
    bzero(&p->po_partner_state, sizeof(p->po_partner_state));
    p->po_actor_state 
	= lacp_actor_partner_state_set_defaulted(p->po_actor_state);
    bondport_assign_to_LAG(p);
    return;
}

static void
bondport_UpdateSelected(bondport_ref p, lacpdu_ref lacpdu_p)
{
    lacp_actor_partner_tlv_ref	actor;
    partner_state_ref		ps;
    LAG_info_ref		ps_li;

    /* compare the PDU's Actor information to our Partner state */
    actor = (lacp_actor_partner_tlv_ref)lacpdu_p->la_actor_tlv;
    ps = &p->po_partner_state;
    ps_li = &ps->ps_lag_info;
    if (lacp_actor_partner_tlv_get_port(actor) != ps->ps_port
	|| (lacp_actor_partner_tlv_get_port_priority(actor)
	    != ps->ps_port_priority)
	|| bcmp(actor->lap_system, &ps_li->li_system, sizeof(ps_li->li_system))
	|| (lacp_actor_partner_tlv_get_system_priority(actor) 
	    != ps_li->li_system_priority)
	|| (lacp_actor_partner_tlv_get_key(actor) != ps_li->li_key)
	|| (lacp_actor_partner_state_aggregatable(actor->lap_state)
	    != lacp_actor_partner_state_aggregatable(ps->ps_state))) {
	bondport_set_selected(p, SelectedState_UNSELECTED);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] updateSelected UNSELECTED\n",
			     bondport_get_name(p));
	}
    }
    return;
}

static void
bondport_RecordPDU(bondport_ref p, lacpdu_ref lacpdu_p)
{
    lacp_actor_partner_tlv_ref	actor;
    ifbond_ref			bond = p->po_bond;
    int				lacp_maintain = 0;
    partner_state_ref		ps;
    lacp_actor_partner_tlv_ref	partner;
    LAG_info_ref		ps_li;

    /* copy the PDU's Actor information into our Partner state */
    actor = (lacp_actor_partner_tlv_ref)lacpdu_p->la_actor_tlv;
    ps = &p->po_partner_state;
    ps_li = &ps->ps_lag_info;
    ps->ps_port = lacp_actor_partner_tlv_get_port(actor);
    ps->ps_port_priority = lacp_actor_partner_tlv_get_port_priority(actor);
    ps_li->li_system = *((lacp_system_ref)actor->lap_system);
    ps_li->li_system_priority 
	= lacp_actor_partner_tlv_get_system_priority(actor);
    ps_li->li_key = lacp_actor_partner_tlv_get_key(actor);
    ps->ps_state = lacp_actor_partner_state_set_out_of_sync(actor->lap_state);
    p->po_actor_state 
	= lacp_actor_partner_state_set_not_defaulted(p->po_actor_state);

    /* compare the PDU's Partner information to our own information */
    partner = (lacp_actor_partner_tlv_ref)lacpdu_p->la_partner_tlv;

    if (lacp_actor_partner_state_active_lacp(ps->ps_state)
	|| (lacp_actor_partner_state_active_lacp(p->po_actor_state)
	    && lacp_actor_partner_state_active_lacp(partner->lap_state))) {
	if (g_bond->verbose) {
	    timestamp_printf("[%s] recordPDU: LACP will maintain\n",
			     bondport_get_name(p));
	}
	lacp_maintain = 1;
    }
    if ((lacp_actor_partner_tlv_get_port(partner) 
	 == bondport_get_index(p))
	&& lacp_actor_partner_tlv_get_port_priority(partner) == p->po_priority
	&& bcmp(partner->lap_system, &g_bond->system, 
		sizeof(g_bond->system)) == 0
	&& (lacp_actor_partner_tlv_get_system_priority(partner) 
	    == g_bond->system_priority)
	&& lacp_actor_partner_tlv_get_key(partner) == bond->ifb_key
	&& (lacp_actor_partner_state_aggregatable(partner->lap_state)
	    == lacp_actor_partner_state_aggregatable(p->po_actor_state))
	&& lacp_actor_partner_state_in_sync(actor->lap_state)
	&& lacp_maintain) {
	ps->ps_state = lacp_actor_partner_state_set_in_sync(ps->ps_state);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] recordPDU: LACP partner in sync\n",
			     bondport_get_name(p));
	}
    }
    else if (lacp_actor_partner_state_aggregatable(actor->lap_state) == 0
	     && lacp_actor_partner_state_in_sync(actor->lap_state)
	     && lacp_maintain) {
	ps->ps_state = lacp_actor_partner_state_set_in_sync(ps->ps_state);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] recordPDU: LACP partner in sync (ind)\n",
			     bondport_get_name(p));
	}
    }
    bondport_assign_to_LAG(p);
    return;
}

static __inline__ lacp_actor_partner_state
updateNTTBits(lacp_actor_partner_state s)
{
    return (s & (LACP_ACTOR_PARTNER_STATE_LACP_ACTIVITY
		 | LACP_ACTOR_PARTNER_STATE_LACP_TIMEOUT
		 | LACP_ACTOR_PARTNER_STATE_AGGREGATION
		 | LACP_ACTOR_PARTNER_STATE_SYNCHRONIZATION));
}

static void
bondport_UpdateNTT(bondport_ref p, lacpdu_ref lacpdu_p)
{
    ifbond_ref			bond = p->po_bond;
    lacp_actor_partner_tlv_ref	partner;

    /* compare the PDU's Actor information to our Partner state */
    partner = (lacp_actor_partner_tlv_ref)lacpdu_p->la_partner_tlv;
    if ((lacp_actor_partner_tlv_get_port(partner) != bondport_get_index(p))
	|| lacp_actor_partner_tlv_get_port_priority(partner) != p->po_priority
	|| bcmp(partner->lap_system, &g_bond->system, sizeof(g_bond->system))
	|| (lacp_actor_partner_tlv_get_system_priority(partner) 
	    != g_bond->system_priority)
	|| lacp_actor_partner_tlv_get_key(partner) != bond->ifb_key
	|| (updateNTTBits(partner->lap_state) 
	    != updateNTTBits(p->po_actor_state))) {
	bondport_flags_set_ntt(p);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] updateNTT: Need To Transmit\n",
			     bondport_get_name(p));
	}
    }
    return;
}

static void
bondport_AttachMuxToAggregator(bondport_ref p)
{
    if (bondport_flags_mux_attached(p) == 0) {
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Attached Mux To Aggregator\n",
			     bondport_get_name(p));
	}
	bondport_flags_set_mux_attached(p);
    }
    return;
}

static void
bondport_DetachMuxFromAggregator(bondport_ref p)
{
    if (bondport_flags_mux_attached(p)) {
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Detached Mux From Aggregator\n",
			     bondport_get_name(p));
	}
	bondport_flags_clear_mux_attached(p);
    }
    return;
}

static void
bondport_enable_distributing(bondport_ref p)
{
    if (bondport_flags_distributing(p) == 0) {
	ifbond_ref	bond = p->po_bond;

	bond->ifb_distributing_array[bond->ifb_distributing_count++] = p;
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Distribution Enabled\n",
			     bondport_get_name(p));
	}
	bondport_flags_set_distributing(p);
    }
    return;
}

static void
bondport_disable_distributing(bondport_ref p)
{
    if (bondport_flags_distributing(p)) {
	bondport_ref *	array;
	ifbond_ref	bond;
	int		count;
	int		i;

	bond = p->po_bond;
	array = bond->ifb_distributing_array;
	count = bond->ifb_distributing_count;
	for (i = 0; i < count; i++) {
	    if (array[i] == p) {
		int	j;

		for (j = i; j < (count - 1); j++) {
		    array[j] = array[j + 1];
		}
		break;
	    }
	}
	bond->ifb_distributing_count--;
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Distribution Disabled\n",
			     bondport_get_name(p));
	}
	bondport_flags_clear_distributing(p);
    }
    return;
}

/**
 ** Receive machine functions
 **/
static void
bondport_receive_machine_initialize(bondport_ref p, LAEvent event,
				    void * event_data);
static void
bondport_receive_machine_port_disabled(bondport_ref p, LAEvent event,
				       void * event_data);
static void
bondport_receive_machine_expired(bondport_ref p, LAEvent event,
				 void * event_data);
static void
bondport_receive_machine_lacp_disabled(bondport_ref p, LAEvent event,
				       void * event_data);
static void
bondport_receive_machine_defaulted(bondport_ref p, LAEvent event,
				   void * event_data);
static void
bondport_receive_machine_current(bondport_ref p, LAEvent event,
				 void * event_data);

static void
bondport_receive_machine_event(bondport_ref p, LAEvent event, 
			       void * event_data)
{
    switch (p->po_receive_state) {
    case ReceiveState_none:
	bondport_receive_machine_initialize(p, LAEventStart, NULL);
	break;
    case ReceiveState_INITIALIZE:
	bondport_receive_machine_initialize(p, event, event_data);
	break;
    case ReceiveState_PORT_DISABLED:
	bondport_receive_machine_port_disabled(p, event, event_data);
	break;
    case ReceiveState_EXPIRED:
	bondport_receive_machine_expired(p, event, event_data);
	break;
    case ReceiveState_LACP_DISABLED:
	bondport_receive_machine_lacp_disabled(p, event, event_data);
	break;
    case ReceiveState_DEFAULTED:
	bondport_receive_machine_defaulted(p, event, event_data);
	break;
    case ReceiveState_CURRENT:
	bondport_receive_machine_current(p, event, event_data);
	break;
    default:
	break;
    }
    return;
}

static void
bondport_receive_machine(bondport_ref p, LAEvent event,
			 void * event_data)
{
    switch (event) {
    case LAEventPacket:
	if (p->po_receive_state != ReceiveState_LACP_DISABLED) {
	    bondport_receive_machine_current(p, event, event_data);
	}
	break;
    case LAEventMediaChange:
	if (media_active(&p->po_media_info)) {
	    switch (p->po_receive_state) {
	    case ReceiveState_PORT_DISABLED:
	    case ReceiveState_LACP_DISABLED:
		bondport_receive_machine_port_disabled(p, LAEventMediaChange, NULL);
		break;
	    default:
		break;
	    }
	}
	else {
	    bondport_receive_machine_port_disabled(p, LAEventStart, NULL);
	}
	break;
    default:
	bondport_receive_machine_event(p, event, event_data);
	break;
    }
    return;
}

static void
bondport_receive_machine_initialize(bondport_ref p, LAEvent event,
				    __unused void * event_data)
{
    switch (event) {
    case LAEventStart:
	devtimer_cancel(p->po_current_while_timer);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Receive INITIALIZE\n",
			     bondport_get_name(p));
	}
	p->po_receive_state = ReceiveState_INITIALIZE;
	bondport_set_selected(p, SelectedState_UNSELECTED);
	bondport_RecordDefault(p);
	p->po_actor_state
	    = lacp_actor_partner_state_set_not_expired(p->po_actor_state);
	bondport_receive_machine_port_disabled(p, LAEventStart, NULL);
	break;
    default:
	break;
    }
    return;
}

static void
bondport_receive_machine_port_disabled(bondport_ref p, LAEvent event,
				       __unused void * event_data)
{
    partner_state_ref	ps;

    switch (event) {
    case LAEventStart:
	devtimer_cancel(p->po_current_while_timer);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Receive PORT_DISABLED\n",
			     bondport_get_name(p));
	}
	p->po_receive_state = ReceiveState_PORT_DISABLED;
	ps = &p->po_partner_state;
	ps->ps_state = lacp_actor_partner_state_set_out_of_sync(ps->ps_state);
	/* FALL THROUGH */
    case LAEventMediaChange:
	if (media_active(&p->po_media_info)) {
	    if (media_full_duplex(&p->po_media_info)) {
		bondport_receive_machine_expired(p, LAEventStart, NULL);
	    }
	    else {
		bondport_receive_machine_lacp_disabled(p, LAEventStart, NULL);
	    }
	}
	else if (p->po_selected == SelectedState_SELECTED) {
	    struct timeval	tv;

	    if (g_bond->verbose) {
		timestamp_printf("[%s] Receive PORT_DISABLED: "
				 "link timer started\n",
				 bondport_get_name(p));
	    }
	    tv.tv_sec = 1;
	    tv.tv_usec = 0;
	    devtimer_set_relative(p->po_current_while_timer, tv, 
				  (devtimer_timeout_func)
				  bondport_receive_machine_port_disabled,
				  (void *)LAEventTimeout, NULL);
	}
	else if (p->po_selected == SelectedState_STANDBY) {
	    bondport_set_selected(p, SelectedState_UNSELECTED);
	}
	break;
    case LAEventTimeout:
	if (p->po_selected == SelectedState_SELECTED) {
	    if (g_bond->verbose) {
		timestamp_printf("[%s] Receive PORT_DISABLED: "
				 "link timer completed, marking UNSELECTED\n",
				 bondport_get_name(p));
	    }
	    bondport_set_selected(p, SelectedState_UNSELECTED);
	}
	break;
    case LAEventPortMoved:
	bondport_receive_machine_initialize(p, LAEventStart, NULL);
	break;
    default:
	break;
    }
    return;
}

static void
bondport_receive_machine_expired(bondport_ref p, LAEvent event,
				 __unused void * event_data)
{
    lacp_actor_partner_state	s;
    struct timeval 		tv;

    switch (event) {
    case LAEventStart:
	devtimer_cancel(p->po_current_while_timer);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Receive EXPIRED\n",
			     bondport_get_name(p));
	}
	p->po_receive_state = ReceiveState_EXPIRED;
	s = p->po_partner_state.ps_state;
	s = lacp_actor_partner_state_set_out_of_sync(s);
	s = lacp_actor_partner_state_set_short_timeout(s);
	p->po_partner_state.ps_state = s;
	p->po_actor_state 
	    = lacp_actor_partner_state_set_expired(p->po_actor_state);
	/* start current_while timer */
	tv.tv_sec = LACP_SHORT_TIMEOUT_TIME;
	tv.tv_usec = 0;
	devtimer_set_relative(p->po_current_while_timer, tv, 
			      (devtimer_timeout_func)
			      bondport_receive_machine_expired,
			      (void *)LAEventTimeout, NULL);

	break;
    case LAEventTimeout:
	bondport_receive_machine_defaulted(p, LAEventStart, NULL);
	break;
    default:
	break;
    }
    return;
}

static void
bondport_receive_machine_lacp_disabled(bondport_ref p, LAEvent event,
				       __unused void * event_data)
{
    partner_state_ref	ps;
    switch (event) {
    case LAEventStart:
	devtimer_cancel(p->po_current_while_timer);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Receive LACP_DISABLED\n",
			     bondport_get_name(p));
	}
	p->po_receive_state = ReceiveState_LACP_DISABLED;
	bondport_set_selected(p, SelectedState_UNSELECTED);
	bondport_RecordDefault(p);
	ps = &p->po_partner_state;
	ps->ps_state = lacp_actor_partner_state_set_individual(ps->ps_state);
	p->po_actor_state
	    = lacp_actor_partner_state_set_not_expired(p->po_actor_state);
	break;
    default:
	break;
    }
    return;
}

static void
bondport_receive_machine_defaulted(bondport_ref p, LAEvent event,
				   __unused void * event_data)
{
    switch (event) {
    case LAEventStart:
	devtimer_cancel(p->po_current_while_timer);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Receive DEFAULTED\n",
			     bondport_get_name(p));
	}
	p->po_receive_state = ReceiveState_DEFAULTED;
	bondport_UpdateDefaultSelected(p);
	bondport_RecordDefault(p);
	p->po_actor_state
	    = lacp_actor_partner_state_set_not_expired(p->po_actor_state);
	break;
    default:
	break;
    }
    return;
}

static void
bondport_receive_machine_current(bondport_ref p, LAEvent event,
				 void * event_data)
{
    partner_state_ref	ps;
    struct timeval	tv;

    switch (event) {
    case LAEventPacket:
	devtimer_cancel(p->po_current_while_timer);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Receive CURRENT\n",
			     bondport_get_name(p));
	}
	p->po_receive_state = ReceiveState_CURRENT;
	bondport_UpdateSelected(p, event_data);
	bondport_UpdateNTT(p, event_data);
	bondport_RecordPDU(p, event_data);
	p->po_actor_state
	    = lacp_actor_partner_state_set_not_expired(p->po_actor_state);
	bondport_assign_to_LAG(p);
	/* start current_while timer */
	ps = &p->po_partner_state;
	if (lacp_actor_partner_state_short_timeout(ps->ps_state)) {
	    tv.tv_sec = LACP_SHORT_TIMEOUT_TIME;
	}
	else {
	    tv.tv_sec = LACP_LONG_TIMEOUT_TIME;
	}
	tv.tv_usec = 0;
	devtimer_set_relative(p->po_current_while_timer, tv,
			      (devtimer_timeout_func)
			      bondport_receive_machine_current,
			      (void *)LAEventTimeout, NULL);
	break;
    case LAEventTimeout:
	bondport_receive_machine_expired(p, LAEventStart, NULL);
	break;
    default:
	break;
    }
    return;
}

/**
 ** Periodic Transmission machine
 **/

static void
bondport_periodic_transmit_machine(bondport_ref p, LAEvent event,
				   __unused void * event_data)
{
    int			interval;
    partner_state_ref	ps;
    struct timeval	tv;

    switch (event) {
    case LAEventStart:
	if (g_bond->verbose) {
	    timestamp_printf("[%s] periodic_transmit Start\n",
			     bondport_get_name(p));
	}
	/* FALL THROUGH */
    case LAEventMediaChange:
	devtimer_cancel(p->po_periodic_timer);
	p->po_periodic_interval = 0;
	if (media_active(&p->po_media_info) == 0
	    || media_full_duplex(&p->po_media_info) == 0) {
	    break;
	}
    case LAEventPacket:
	/* Neither Partner nor Actor are LACP Active, no periodic tx */
	ps = &p->po_partner_state;
	if (lacp_actor_partner_state_active_lacp(p->po_actor_state) == 0
	    && (lacp_actor_partner_state_active_lacp(ps->ps_state) 
		== 0)) {
	    devtimer_cancel(p->po_periodic_timer);
	    p->po_periodic_interval = 0;
	    break;
	}
	if (lacp_actor_partner_state_short_timeout(ps->ps_state)) {
	    interval = LACP_FAST_PERIODIC_TIME;
	}
	else {
	    interval = LACP_SLOW_PERIODIC_TIME;
	}
	if (p->po_periodic_interval != interval) {
	    if (interval == LACP_FAST_PERIODIC_TIME
		&& p->po_periodic_interval == LACP_SLOW_PERIODIC_TIME) {
		if (g_bond->verbose) {
		    timestamp_printf("[%s] periodic_transmit:"
				     " Need To Transmit\n",
				     bondport_get_name(p));
		}
		bondport_flags_set_ntt(p);
	    }
	    p->po_periodic_interval = interval;
	    tv.tv_usec = 0;
	    tv.tv_sec = interval;
	    devtimer_set_relative(p->po_periodic_timer, tv, 
				  (devtimer_timeout_func)
				  bondport_periodic_transmit_machine,
				  (void *)LAEventTimeout, NULL);
	    if (g_bond->verbose) {
		timestamp_printf("[%s] Periodic Transmission Timer: %d secs\n",
				 bondport_get_name(p), 
				 p->po_periodic_interval);
	    }
	}
	break;
    case LAEventTimeout:
	bondport_flags_set_ntt(p);
	tv.tv_sec = p->po_periodic_interval;
	tv.tv_usec = 0;
	devtimer_set_relative(p->po_periodic_timer, tv, (devtimer_timeout_func)
			      bondport_periodic_transmit_machine,
			      (void *)LAEventTimeout, NULL);
	if (g_bond->verbose > 1) {
	    timestamp_printf("[%s] Periodic Transmission Timer: %d secs\n",
			     bondport_get_name(p), p->po_periodic_interval);
	}
	break;
    default:
	break;
    }
    return;
}

/**
 ** Transmit machine
 **/
static int
bondport_can_transmit(bondport_ref p, int32_t current_secs,
		      __darwin_time_t * next_secs)
{
    if (p->po_last_transmit_secs != current_secs) {
	p->po_last_transmit_secs = current_secs;
	p->po_n_transmit = 0;
    }
    if (p->po_n_transmit < LACP_PACKET_RATE) {
	p->po_n_transmit++;
	return (1);
    }
    if (next_secs != NULL) {
	*next_secs = current_secs + 1;
    }
    return (0);
}

static void
bondport_transmit_machine(bondport_ref p, LAEvent event,
			  void * event_data)
{
    lacp_actor_partner_tlv_ref	aptlv;
    lacp_collector_tlv_ref	ctlv;
    struct timeval		next_tick_time = {0, 0};
    lacpdu_ref		out_lacpdu_p;
    packet_buffer_ref		pkt;
    partner_state_ref		ps;
    LAG_info_ref		ps_li;

    switch (event) {
    case LAEventTimeout:
    case LAEventStart:
	if (p->po_periodic_interval == 0 || bondport_flags_ntt(p) == 0) {
	    break;
	}
	if (event_data == TRANSMIT_MACHINE_TX_IMMEDIATE) {
	    /* we're going away, transmit the packet no matter what */
	}
	else if (bondport_can_transmit(p, devtimer_current_secs(),
				       &next_tick_time.tv_sec) == 0) {
	    if (devtimer_enabled(p->po_transmit_timer)) {
		if (g_bond->verbose > 0) {
		    timestamp_printf("[%s] Transmit Timer Already Set\n",
				     bondport_get_name(p));
		}
	    }
	    else {
		devtimer_set_absolute(p->po_transmit_timer, next_tick_time,
				      (devtimer_timeout_func)
				      bondport_transmit_machine,
				      (void *)LAEventTimeout, NULL);
		if (g_bond->verbose > 0) {
		    timestamp_printf("[%s] Transmit Timer Deadline %d secs\n",
				     bondport_get_name(p),
				     (int)next_tick_time.tv_sec);
		}
	    }
	    break;
	}
	if (g_bond->verbose > 0) {
	    if (event == LAEventTimeout) {
		timestamp_printf("[%s] Transmit Timer Complete\n",
				 bondport_get_name(p));
	    }
	}
	pkt = packet_buffer_allocate(sizeof(*out_lacpdu_p));
	if (pkt == NULL) {
	    printf("[%s] Transmit: failed to allocate packet buffer\n",
		   bondport_get_name(p));
	    break;
	}
	out_lacpdu_p = (lacpdu_ref)packet_buffer_byteptr(pkt);
	bzero(out_lacpdu_p, sizeof(*out_lacpdu_p));
	out_lacpdu_p->la_subtype = IEEE8023AD_SLOW_PROTO_SUBTYPE_LACP;
	out_lacpdu_p->la_version = LACPDU_VERSION_1;

	/* Actor */
	aptlv = (lacp_actor_partner_tlv_ref)out_lacpdu_p->la_actor_tlv;
	aptlv->lap_tlv_type = LACPDU_TLV_TYPE_ACTOR;
	aptlv->lap_length = LACPDU_ACTOR_TLV_LENGTH;
	*((lacp_system_ref)aptlv->lap_system) = g_bond->system;
	lacp_actor_partner_tlv_set_system_priority(aptlv, 
						   g_bond->system_priority);
	lacp_actor_partner_tlv_set_port_priority(aptlv, p->po_priority);
	lacp_actor_partner_tlv_set_port(aptlv, bondport_get_index(p));
	lacp_actor_partner_tlv_set_key(aptlv, p->po_bond->ifb_key);
	aptlv->lap_state = p->po_actor_state;

	/* Partner */
	aptlv = (lacp_actor_partner_tlv_ref)out_lacpdu_p->la_partner_tlv;
	aptlv->lap_tlv_type = LACPDU_TLV_TYPE_PARTNER;
	aptlv->lap_length = LACPDU_PARTNER_TLV_LENGTH;
	ps = &p->po_partner_state;
	ps_li = &ps->ps_lag_info;
	lacp_actor_partner_tlv_set_port(aptlv, ps->ps_port);
	lacp_actor_partner_tlv_set_port_priority(aptlv, ps->ps_port_priority);
	*((lacp_system_ref)aptlv->lap_system) = ps_li->li_system;
	lacp_actor_partner_tlv_set_system_priority(aptlv, 
						   ps_li->li_system_priority);
	lacp_actor_partner_tlv_set_key(aptlv, ps_li->li_key);
	aptlv->lap_state = ps->ps_state;

	/* Collector */
	ctlv = (lacp_collector_tlv_ref)out_lacpdu_p->la_collector_tlv;
	ctlv->lac_tlv_type = LACPDU_TLV_TYPE_COLLECTOR;
	ctlv->lac_length = LACPDU_COLLECTOR_TLV_LENGTH;

	bondport_slow_proto_transmit(p, pkt);
	bondport_flags_clear_ntt(p);
	if (g_bond->verbose > 0) {
	    timestamp_printf("[%s] Transmit Packet %d\n",
			     bondport_get_name(p), p->po_n_transmit);
	}
	break;
    default:
	break;
    }
    return;
}

/**
 ** Mux machine functions
 **/

static void
bondport_mux_machine_detached(bondport_ref p, LAEvent event,
			      void * event_data);
static void
bondport_mux_machine_waiting(bondport_ref p, LAEvent event,
			     void * event_data);
static void
bondport_mux_machine_attached(bondport_ref p, LAEvent event,
			      void * event_data);

static void
bondport_mux_machine_collecting_distributing(bondport_ref p, LAEvent event,
					     void * event_data);

static void
bondport_mux_machine(bondport_ref p, LAEvent event, void * event_data)
{
    switch (p->po_mux_state) {
    case MuxState_none:
	bondport_mux_machine_detached(p, LAEventStart, NULL);
	break;
    case MuxState_DETACHED:
	bondport_mux_machine_detached(p, event, event_data);
	break;
    case MuxState_WAITING:
	bondport_mux_machine_waiting(p, event, event_data);
	break;
    case MuxState_ATTACHED:
	bondport_mux_machine_attached(p, event, event_data);
	break;
    case MuxState_COLLECTING_DISTRIBUTING:
	bondport_mux_machine_collecting_distributing(p, event, event_data);
	break;
    default:
	break;
    }
    return;
}

static void
bondport_mux_machine_detached(bondport_ref p, LAEvent event,
			      __unused void * event_data)
{
    lacp_actor_partner_state	s;

    switch (event) {
    case LAEventStart:
	devtimer_cancel(p->po_wait_while_timer);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Mux DETACHED\n",
			     bondport_get_name(p));
	}
	p->po_mux_state = MuxState_DETACHED;
	bondport_flags_clear_ready(p);
	bondport_DetachMuxFromAggregator(p);
	bondport_disable_distributing(p);
	s = p->po_actor_state;
	s = lacp_actor_partner_state_set_out_of_sync(s);
	s = lacp_actor_partner_state_set_not_collecting(s);
	s = lacp_actor_partner_state_set_not_distributing(s);
	p->po_actor_state = s;
	bondport_flags_set_ntt(p);
	break;
    case LAEventSelectedChange:
    case LAEventPacket:
    case LAEventMediaChange:
	if (p->po_selected == SelectedState_SELECTED
	    || p->po_selected == SelectedState_STANDBY) {
	    bondport_mux_machine_waiting(p, LAEventStart, NULL);
	}
	break;
    default:
	break;
    }
    return;
}

static void
bondport_mux_machine_waiting(bondport_ref p, LAEvent event,
			     __unused void * event_data)
{
    struct timeval	tv;

    switch (event) {
    case LAEventStart:
	devtimer_cancel(p->po_wait_while_timer);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Mux WAITING\n", 
			     bondport_get_name(p));
	}
	p->po_mux_state = MuxState_WAITING;
	/* FALL THROUGH */
    default:
    case LAEventSelectedChange:
	if (p->po_selected == SelectedState_UNSELECTED) {
	    bondport_mux_machine_detached(p, LAEventStart, NULL);
	    break;
	}
	if (p->po_selected == SelectedState_STANDBY) {
	    devtimer_cancel(p->po_wait_while_timer);
	    /* wait until state changes to SELECTED */
	    if (g_bond->verbose) {
		timestamp_printf("[%s] Mux WAITING: Standby\n",
				 bondport_get_name(p));
	    }
	    break;
	}
	if (bondport_flags_ready(p)) {
	    if (g_bond->verbose) {
		timestamp_printf("[%s] Mux WAITING: Port is already ready\n",
				 bondport_get_name(p));
	    }
	    break;
	}
	if (devtimer_enabled(p->po_wait_while_timer)) {
	    if (g_bond->verbose) {
		timestamp_printf("[%s] Mux WAITING: Timer already set\n",
				 bondport_get_name(p));
	    }
	    break;
	}
	if (ifbond_all_ports_attached(p->po_bond, p)) {
	    devtimer_cancel(p->po_wait_while_timer);
	    if (g_bond->verbose) {
		timestamp_printf("[%s] Mux WAITING: No waiting\n",
				 bondport_get_name(p));
	    }
	    bondport_flags_set_ready(p);
	    goto no_waiting;
	}
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Mux WAITING: 2 seconds\n", 
			     bondport_get_name(p));
	}
	tv.tv_sec = LACP_AGGREGATE_WAIT_TIME;
	tv.tv_usec = 0;
	devtimer_set_relative(p->po_wait_while_timer, tv, 
			      (devtimer_timeout_func)
			      bondport_mux_machine_waiting,
			      (void *)LAEventTimeout, NULL);
	break;
    case LAEventTimeout:
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Mux WAITING: Ready\n", 
			     bondport_get_name(p));
	}
	bondport_flags_set_ready(p);
	break;
    case LAEventReady:
    no_waiting:
	if (bondport_flags_ready(p)){
	    if (g_bond->verbose) {
		timestamp_printf("[%s] Mux WAITING: All Ports Ready\n", 
				 bondport_get_name(p));
	    }
	    bondport_mux_machine_attached(p, LAEventStart, NULL);
	    break;
	}
	break;
    }
    return;
}

static void
bondport_mux_machine_attached(bondport_ref p, LAEvent event,
			      __unused void * event_data)
{
    lacp_actor_partner_state	s;

    switch (event) {
    case LAEventStart:
	devtimer_cancel(p->po_wait_while_timer);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Mux ATTACHED\n",
			     bondport_get_name(p));
	}
	p->po_mux_state = MuxState_ATTACHED;
	bondport_AttachMuxToAggregator(p);
	s = p->po_actor_state;
	s = lacp_actor_partner_state_set_in_sync(s);
	s = lacp_actor_partner_state_set_not_collecting(s);
	s = lacp_actor_partner_state_set_not_distributing(s);
	bondport_disable_distributing(p);
	p->po_actor_state = s;
	bondport_flags_set_ntt(p);
	/* FALL THROUGH */
    default:
	switch (p->po_selected) {
	case SelectedState_SELECTED:
	    s = p->po_partner_state.ps_state;
	    if (lacp_actor_partner_state_in_sync(s)) {
		bondport_mux_machine_collecting_distributing(p, LAEventStart, 
							     NULL);
	    }
	    break;
	default:
	    bondport_mux_machine_detached(p, LAEventStart, NULL);
	    break;
	}
	break;
    }
    return;
}

static void
bondport_mux_machine_collecting_distributing(bondport_ref p, 
					     LAEvent event,
					     __unused void * event_data)
{
    lacp_actor_partner_state	s;

    switch (event) {
    case LAEventStart:
	devtimer_cancel(p->po_wait_while_timer);
	if (g_bond->verbose) {
	    timestamp_printf("[%s] Mux COLLECTING_DISTRIBUTING\n", 
			     bondport_get_name(p));
	}
	p->po_mux_state = MuxState_COLLECTING_DISTRIBUTING;
	bondport_enable_distributing(p);
	s = p->po_actor_state;
	s = lacp_actor_partner_state_set_collecting(s);
	s = lacp_actor_partner_state_set_distributing(s);
	p->po_actor_state = s;
	bondport_flags_set_ntt(p);
	/* FALL THROUGH */
    default:
	s = p->po_partner_state.ps_state;
	if (lacp_actor_partner_state_in_sync(s) == 0) {
	    bondport_mux_machine_attached(p, LAEventStart, NULL);
	    break;
	}
	switch (p->po_selected) {
	case SelectedState_UNSELECTED:
	case SelectedState_STANDBY:
	    bondport_mux_machine_attached(p, LAEventStart, NULL);
	    break;
	default:
	    break;
	}
	break;
    }
    return;
}
