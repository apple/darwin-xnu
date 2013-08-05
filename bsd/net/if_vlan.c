/*
 * Copyright (c) 2003-2013 Apple Inc. All rights reserved.
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
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/net/if_vlan.c,v 1.54 2003/10/31 18:32:08 brooks Exp $
 */

/*
 * if_vlan.c - pseudo-device driver for IEEE 802.1Q virtual LANs.
 * Might be extended some day to also handle IEEE 802.1p priority
 * tagging.  This is sort of sneaky in the implementation, since
 * we need to pretend to be enough of an Ethernet implementation
 * to make arp work.  The way we do this is by telling everyone
 * that we are an Ethernet, and then catch the packets that
 * ether_output() left on our output queue when it calls
 * if_start(), rewrite them for use by the real outgoing interface,
 * and ask it to send them.
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

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>
#include <libkern/OSAtomic.h>

#include <net/dlil.h>

#include <net/kpi_interface.h>
#include <net/kpi_protocol.h>

#include <kern/locks.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/if_ether.h>
#endif

#include <net/if_media.h>
#include <net/multicast_list.h>
#include <net/ether_if_module.h>

#define VLANNAME	"vlan"

typedef int (bpf_callback_func)(struct ifnet *, struct mbuf *);
typedef int (if_set_bpf_tap_func)(struct ifnet *ifp, int mode, bpf_callback_func * func);

/**
 ** vlan locks
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

static lck_mtx_t * 	vlan_lck_mtx;

static __inline__ void
vlan_lock_init(void)
{
    lck_grp_t *		vlan_lck_grp;

    vlan_lck_grp = my_lck_grp_alloc_init("if_vlan");
    vlan_lck_mtx = my_lck_mtx_alloc_init(vlan_lck_grp);
}

static __inline__ void
vlan_assert_lock_held(void)
{
    lck_mtx_assert(vlan_lck_mtx, LCK_MTX_ASSERT_OWNED);
    return;
}

static __inline__ void
vlan_assert_lock_not_held(void)
{
    lck_mtx_assert(vlan_lck_mtx, LCK_MTX_ASSERT_NOTOWNED);
    return;
}

static __inline__ void
vlan_lock(void)
{
    lck_mtx_lock(vlan_lck_mtx);
    return;
}

static __inline__ void
vlan_unlock(void)
{
    lck_mtx_unlock(vlan_lck_mtx);
    return;
}

/**
 ** vlan structures, types
 **/
struct vlan_parent;
LIST_HEAD(vlan_parent_list, vlan_parent);
struct ifvlan;
LIST_HEAD(ifvlan_list, ifvlan);

typedef LIST_ENTRY(vlan_parent) 
vlan_parent_entry;
typedef LIST_ENTRY(ifvlan) 
ifvlan_entry;

#define VLP_SIGNATURE		0xfaceface
typedef struct vlan_parent {
    vlan_parent_entry		vlp_parent_list;/* list of parents */
    struct ifnet *		vlp_ifp;	/* interface */
    struct ifvlan_list		vlp_vlan_list;	/* list of VLAN's */
#define VLPF_SUPPORTS_VLAN_MTU	0x1
#define VLPF_CHANGE_IN_PROGRESS	0x2
#define VLPF_DETACHING		0x4
    u_int32_t			vlp_flags;
    struct ifdevmtu		vlp_devmtu;
    SInt32			vlp_retain_count;
    UInt32			vlp_signature;	/* VLP_SIGNATURE */
} vlan_parent, * vlan_parent_ref;

#define IFV_SIGNATURE		0xbeefbeef
struct ifvlan {
    ifvlan_entry 		ifv_vlan_list;
    char			ifv_name[IFNAMSIZ]; /* our unique id */
    struct ifnet *		ifv_ifp;	/* our interface */
    vlan_parent_ref		ifv_vlp;	/* parent information */
    struct	ifv_linkmib {
	u_int16_t ifvm_encaplen;/* encapsulation length */
	u_int16_t ifvm_mtufudge;/* MTU fudged by this much */
	u_int16_t ifvm_proto;	/* encapsulation ethertype */
	u_int16_t ifvm_tag; 	/* tag to apply on packets leaving if */
    }	ifv_mib;
    struct multicast_list 	ifv_multicast;
#define	IFVF_PROMISC		0x1		/* promiscuous mode enabled */
#define IFVF_DETACHING		0x2		/* interface is detaching */
#define IFVF_READY		0x4		/* interface is ready */
    u_int32_t			ifv_flags;
    bpf_packet_func		ifv_bpf_input;
    bpf_packet_func		ifv_bpf_output;
    SInt32			ifv_retain_count;
    UInt32			ifv_signature;	/* IFV_SIGNATURE */
};

typedef struct ifvlan * ifvlan_ref;

typedef struct vlan_globals_s {
    struct vlan_parent_list	parent_list;
    int				verbose;
} * vlan_globals_ref;
    
static vlan_globals_ref	g_vlan;

#define	ifv_tag		ifv_mib.ifvm_tag
#define	ifv_encaplen	ifv_mib.ifvm_encaplen
#define	ifv_mtufudge	ifv_mib.ifvm_mtufudge

static void
vlan_parent_retain(vlan_parent_ref vlp);

static void
vlan_parent_release(vlan_parent_ref vlp);

/**
 ** vlan_parent_ref vlp_flags in-lines
 **/
static __inline__ int
vlan_parent_flags_supports_vlan_mtu(vlan_parent_ref vlp)
{
    return ((vlp->vlp_flags & VLPF_SUPPORTS_VLAN_MTU) != 0);
}

static __inline__ void
vlan_parent_flags_set_supports_vlan_mtu(vlan_parent_ref vlp)
{
    vlp->vlp_flags |= VLPF_SUPPORTS_VLAN_MTU;
    return;
}

static __inline__ void
vlan_parent_flags_clear_supports_vlan_mtu(vlan_parent_ref vlp)
{
    vlp->vlp_flags &= ~VLPF_SUPPORTS_VLAN_MTU;
    return;
}

static __inline__ int
vlan_parent_flags_change_in_progress(vlan_parent_ref vlp)
{
    return ((vlp->vlp_flags & VLPF_CHANGE_IN_PROGRESS) != 0);
}

static __inline__ void
vlan_parent_flags_set_change_in_progress(vlan_parent_ref vlp)
{
    vlp->vlp_flags |= VLPF_CHANGE_IN_PROGRESS;
    return;
}

static __inline__ void
vlan_parent_flags_clear_change_in_progress(vlan_parent_ref vlp)
{
    vlp->vlp_flags &= ~VLPF_CHANGE_IN_PROGRESS;
    return;
}

static __inline__ int
vlan_parent_flags_detaching(struct vlan_parent * vlp)
{
    return ((vlp->vlp_flags & VLPF_DETACHING) != 0);
}

static __inline__ void
vlan_parent_flags_set_detaching(struct vlan_parent * vlp)
{
    vlp->vlp_flags |= VLPF_DETACHING;
    return;
}


/**
 ** ifvlan_flags in-lines routines
 **/
static __inline__ int
ifvlan_flags_promisc(ifvlan_ref ifv)
{
    return ((ifv->ifv_flags & IFVF_PROMISC) != 0);
}

static __inline__ void
ifvlan_flags_set_promisc(ifvlan_ref ifv)
{
    ifv->ifv_flags |= IFVF_PROMISC;
    return;
}

static __inline__ void
ifvlan_flags_clear_promisc(ifvlan_ref ifv)
{
    ifv->ifv_flags &= ~IFVF_PROMISC;
    return;
}

static __inline__ int
ifvlan_flags_ready(ifvlan_ref ifv)
{
    return ((ifv->ifv_flags & IFVF_READY) != 0);
}

static __inline__ void
ifvlan_flags_set_ready(ifvlan_ref ifv)
{
    ifv->ifv_flags |= IFVF_READY;
    return;
}

static __inline__ void
ifvlan_flags_clear_ready(ifvlan_ref ifv)
{
    ifv->ifv_flags &= ~IFVF_READY;
    return;
}

static __inline__ int
ifvlan_flags_detaching(ifvlan_ref ifv)
{
    return ((ifv->ifv_flags & IFVF_DETACHING) != 0);
}

static __inline__ void
ifvlan_flags_set_detaching(ifvlan_ref ifv)
{
    ifv->ifv_flags |= IFVF_DETACHING;
    return;
}

#if 0
SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, IFT_L2VLAN, vlan, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "IEEE 802.1Q VLAN");
SYSCTL_NODE(_net_link_vlan, PF_LINK, link, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "for consistency");
#endif

#define M_VLAN 		M_DEVBUF

static	int vlan_clone_create(struct if_clone *, u_int32_t, void *);
static	int vlan_clone_destroy(struct ifnet *);
static	int vlan_input(ifnet_t ifp, protocol_family_t protocol,
					   mbuf_t m, char *frame_header);
static	int vlan_output(struct ifnet *ifp, struct mbuf *m);
static	int vlan_ioctl(ifnet_t ifp, u_long cmd, void * addr);
static  int vlan_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode,
			     bpf_packet_func func);
static 	int vlan_attach_protocol(struct ifnet *ifp);
static	int vlan_detach_protocol(struct ifnet *ifp);
static	int vlan_setmulti(struct ifnet *ifp);
static	int vlan_unconfig(ifvlan_ref ifv, int need_to_wait);
static 	int vlan_config(struct ifnet * ifp, struct ifnet * p, int tag);
static	void vlan_if_free(struct ifnet * ifp);
static 	int vlan_remove(ifvlan_ref ifv, int need_to_wait);

static struct if_clone vlan_cloner = IF_CLONE_INITIALIZER(VLANNAME,
							  vlan_clone_create, 
							  vlan_clone_destroy, 
							  0, 
							  IF_MAXUNIT);
static	void interface_link_event(struct ifnet * ifp, u_int32_t event_code);
static	void vlan_parent_link_event(struct ifnet * p,
				    u_int32_t event_code);

static 	int ifvlan_new_mtu(ifvlan_ref ifv, int mtu);

/**
 ** ifvlan_ref routines
 **/
static void
ifvlan_retain(ifvlan_ref ifv)
{
    if (ifv->ifv_signature != IFV_SIGNATURE) {
	panic("ifvlan_retain: bad signature\n");
    }
    if (ifv->ifv_retain_count == 0) {
	panic("ifvlan_retain: retain count is 0\n");
    }
    OSIncrementAtomic(&ifv->ifv_retain_count);
}

static void
ifvlan_release(ifvlan_ref ifv)
{
    UInt32		old_retain_count;

    if (ifv->ifv_signature != IFV_SIGNATURE) {
	panic("ifvlan_release: bad signature\n");
    }
    old_retain_count = OSDecrementAtomic(&ifv->ifv_retain_count);
    switch (old_retain_count) {
    case 0:
	panic("ifvlan_release: retain count is 0\n");
	break;
    case 1:
	if (g_vlan->verbose) {
	    printf("ifvlan_release(%s)\n", ifv->ifv_name);
	}
	ifv->ifv_signature = 0;
	FREE(ifv, M_VLAN);
	break;
    default:
	break;
    }
    return;
}

static vlan_parent_ref
ifvlan_get_vlan_parent_retained(ifvlan_ref ifv)
{
    vlan_parent_ref	vlp = ifv->ifv_vlp;

    if (vlan_parent_flags_detaching(vlp)) {
	return (NULL);
    }
    vlan_parent_retain(vlp);
    return (vlp);
}

/**
 ** ifnet_* routines
 **/

static ifvlan_ref
ifnet_get_ifvlan(struct ifnet * ifp)
{
    ifvlan_ref		ifv;

    ifv = (ifvlan_ref)ifnet_softc(ifp);
    return (ifv);
}

static ifvlan_ref
ifnet_get_ifvlan_retained(struct ifnet * ifp)
{
    ifvlan_ref		ifv;

    ifv = ifnet_get_ifvlan(ifp);
    if (ifv == NULL) {
	return (NULL);
    }
    if (ifvlan_flags_detaching(ifv)) {
	return (NULL);
    }
    ifvlan_retain(ifv);
    return (ifv);
}

static int
ifnet_ifvlan_vlan_parent_ok(struct ifnet * ifp, ifvlan_ref ifv,
			    vlan_parent_ref vlp)
{
    ifvlan_ref		check_ifv;

    check_ifv = ifnet_get_ifvlan(ifp);
    if (check_ifv != ifv || ifvlan_flags_detaching(ifv)) {
	/* ifvlan_ref no longer valid */
	return (FALSE);
    }
    if (ifv->ifv_vlp != vlp) {
	/* vlan_parent no longer valid */
	return (FALSE);
    }
    if (vlan_parent_flags_detaching(vlp)) {
	/* parent is detaching */
	return (FALSE);
    }
    return (TRUE);
}

/**
 ** vlan, etc. routines
 **/

static int
vlan_globals_init(void)
{
    vlan_globals_ref	v;

    vlan_assert_lock_not_held();

    if (g_vlan != NULL) {
	return (0);
    }
    v = _MALLOC(sizeof(*v), M_VLAN, M_WAITOK);
    if (v != NULL) {
	LIST_INIT(&v->parent_list);
	v->verbose = 0;
    }
    vlan_lock();
    if (g_vlan != NULL) {
	vlan_unlock();
	if (v != NULL) {
	    _FREE(v, M_VLAN);
	}
	return (0);
    }
    g_vlan = v;
    vlan_unlock();
    if (v == NULL) {
	return (ENOMEM);
    }
    return (0);
}

static int
siocgifdevmtu(struct ifnet * ifp, struct ifdevmtu * ifdm_p)
{
    struct ifreq	ifr;
    int 		error;

    bzero(&ifr, sizeof(ifr));
    error = ifnet_ioctl(ifp, 0,SIOCGIFDEVMTU, &ifr);
    if (error == 0) {
	*ifdm_p = ifr.ifr_devmtu;
    }
    return (error);
}

static int
siocsifaltmtu(struct ifnet * ifp, int mtu)
{
    struct ifreq	ifr;

    bzero(&ifr, sizeof(ifr));
    ifr.ifr_mtu = mtu;
    return (ifnet_ioctl(ifp, 0, SIOCSIFALTMTU, &ifr));
}

static __inline__ void 
vlan_bpf_output(struct ifnet * ifp, struct mbuf * m, 
		bpf_packet_func func)
{
    if (func != NULL) {
	(*func)(ifp, m);
    }
    return;
}

static __inline__ void 
vlan_bpf_input(struct ifnet * ifp, struct mbuf * m, 
	       bpf_packet_func func, char * frame_header,
	       int frame_header_len, int encap_len)
{
    if (func != NULL) {
	if (encap_len > 0) {
	    /* present the right header to bpf */
	    bcopy(frame_header, frame_header + encap_len, frame_header_len);
	}
	m->m_data -= frame_header_len;
	m->m_len += frame_header_len;
	(*func)(ifp, m);
	m->m_data += frame_header_len;
	m->m_len -= frame_header_len;
	if (encap_len > 0) {
	    /* restore the header */
	    bcopy(frame_header + encap_len, frame_header, frame_header_len);
	}
    }
    return;
}

/**
 ** vlan_parent synchronization routines
 **/
static void
vlan_parent_retain(vlan_parent_ref vlp)
{
    if (vlp->vlp_signature != VLP_SIGNATURE) {
	panic("vlan_parent_retain: signature is bad\n");
    }
    if (vlp->vlp_retain_count == 0) {
	panic("vlan_parent_retain: retain count is 0\n");
    }
    OSIncrementAtomic(&vlp->vlp_retain_count);
}

static void
vlan_parent_release(vlan_parent_ref vlp)
{
    UInt32		old_retain_count;

    if (vlp->vlp_signature != VLP_SIGNATURE) {
	panic("vlan_parent_release: signature is bad\n");
    }
    old_retain_count = OSDecrementAtomic(&vlp->vlp_retain_count);
    switch (old_retain_count) {
    case 0:
	panic("vlan_parent_release: retain count is 0\n");
	break;
    case 1:
	if (g_vlan->verbose) {
	    struct ifnet * ifp = vlp->vlp_ifp;
	    printf("vlan_parent_release(%s%d)\n", ifnet_name(ifp),
		   ifnet_unit(ifp));
	}
	vlp->vlp_signature = 0;
	FREE(vlp, M_VLAN);
	break;
    default:
	break;
    }
    return;
}

/*
 * Function: vlan_parent_wait
 * Purpose:
 *   Allows a single thread to gain exclusive access to the vlan_parent
 *   data structure.  Some operations take a long time to complete, 
 *   and some have side-effects that we can't predict.  Holding the
 *   vlan_lock() across such operations is not possible.
 *
 * Notes:
 *   Before calling, you must be holding the vlan_lock and have taken
 *   a reference on the vlan_parent_ref.
 */
static void
vlan_parent_wait(vlan_parent_ref vlp, const char * msg)
{
    int		waited = 0;

    /* other add/remove/multicast-change in progress */
    while (vlan_parent_flags_change_in_progress(vlp)) {
	if (g_vlan->verbose) {
	    struct ifnet * ifp = vlp->vlp_ifp;

	    printf("%s%d: %s msleep\n", ifnet_name(ifp), ifnet_unit(ifp), msg);
	}
	waited = 1;
	(void)msleep(vlp, vlan_lck_mtx, PZERO, msg, 0);
    }
    /* prevent other vlan parent remove/add from taking place */
    vlan_parent_flags_set_change_in_progress(vlp);
    if (g_vlan->verbose && waited) {
	struct ifnet * ifp = vlp->vlp_ifp;

	printf("%s%d: %s woke up\n", ifnet_name(ifp), ifnet_unit(ifp), msg);
    }
    return;
}

/*
 * Function: vlan_parent_signal
 * Purpose:
 *   Allows the thread that previously invoked vlan_parent_wait() to 
 *   give up exclusive access to the vlan_parent data structure, and wake up
 *   any other threads waiting to access
 * Notes:
 *   Before calling, you must be holding the vlan_lock and have taken
 *   a reference on the vlan_parent_ref.
 */
static void
vlan_parent_signal(vlan_parent_ref vlp, const char * msg)
{
    vlan_parent_flags_clear_change_in_progress(vlp);
    wakeup((caddr_t)vlp);
    if (g_vlan->verbose) {
	struct ifnet * ifp = vlp->vlp_ifp;

	printf("%s%d: %s wakeup\n", ifnet_name(ifp), ifnet_unit(ifp), msg);
    }
    return;
}

/*
 * Program our multicast filter. What we're actually doing is
 * programming the multicast filter of the parent. This has the
 * side effect of causing the parent interface to receive multicast
 * traffic that it doesn't really want, which ends up being discarded
 * later by the upper protocol layers. Unfortunately, there's no way
 * to avoid this: there really is only one physical interface.
 */
static int
vlan_setmulti(struct ifnet * ifp)
{
    int			error = 0;
    ifvlan_ref 		ifv;
    struct ifnet *	p;
    vlan_parent_ref	vlp = NULL;

    vlan_lock();
    ifv = ifnet_get_ifvlan_retained(ifp);
    if (ifv == NULL) {
	goto unlock_done;
    }
    vlp = ifvlan_get_vlan_parent_retained(ifv);
    if (vlp == NULL) {
	/* no parent, no need to program the multicast filter */
	goto unlock_done;
    }
    vlan_parent_wait(vlp, "vlan_setmulti");

    /* check again, things could have changed */
    if (ifnet_ifvlan_vlan_parent_ok(ifp, ifv, vlp) == FALSE) {
	goto signal_done;
    }
    p = vlp->vlp_ifp;
    vlan_unlock();

    /* update parent interface with our multicast addresses */
    error = multicast_list_program(&ifv->ifv_multicast, ifp, p);

    vlan_lock();

 signal_done:
    vlan_parent_signal(vlp, "vlan_setmulti");

 unlock_done:
    vlan_unlock();
    if (ifv != NULL) {
	ifvlan_release(ifv);
    }
    if (vlp != NULL) {
	vlan_parent_release(vlp);
    }
    return (error);
}

/**
 ** vlan_parent list manipulation/lookup routines
 **/
static vlan_parent_ref
parent_list_lookup(struct ifnet * p)
{
    vlan_parent_ref	vlp;

    LIST_FOREACH(vlp, &g_vlan->parent_list, vlp_parent_list) {
	if (vlp->vlp_ifp == p) {
	    return (vlp);
	}
    }
    return (NULL);
}

static ifvlan_ref
vlan_parent_lookup_tag(vlan_parent_ref vlp, int tag)
{
    ifvlan_ref		ifv;

    LIST_FOREACH(ifv, &vlp->vlp_vlan_list, ifv_vlan_list) {
	if (tag == ifv->ifv_tag) {
	    return (ifv);
	}
    }
    return (NULL);
}

static ifvlan_ref 
vlan_lookup_parent_and_tag(struct ifnet * p, int tag)
{
    vlan_parent_ref	vlp;

    vlp = parent_list_lookup(p);
    if (vlp != NULL) {
	return (vlan_parent_lookup_tag(vlp, tag));
    }
    return (NULL);
}

static int
vlan_parent_find_max_mtu(vlan_parent_ref vlp, ifvlan_ref exclude_ifv)
{
    int			max_mtu = 0;
    ifvlan_ref		ifv;

    LIST_FOREACH(ifv, &vlp->vlp_vlan_list, ifv_vlan_list) {
	int	req_mtu;

	if (exclude_ifv == ifv) {
	    continue;
	}
	req_mtu = ifnet_mtu(ifv->ifv_ifp) + ifv->ifv_mtufudge;
	if (req_mtu > max_mtu) {
	    max_mtu = req_mtu;
	}
    }
    return (max_mtu);
}

/*
 * Function: vlan_parent_create
 * Purpose:
 *   Create a vlan_parent structure to hold the VLAN's for the given
 *   interface.  Add it to the list of VLAN parents.
 */
static int
vlan_parent_create(struct ifnet * p, vlan_parent_ref * ret_vlp)
{
    int			error;
    vlan_parent_ref	vlp;

    *ret_vlp = NULL;
    vlp = _MALLOC(sizeof(*vlp), M_VLAN, M_WAITOK);
    if (vlp == NULL) {
	return (ENOMEM);
    }
    bzero(vlp, sizeof(*vlp));
    error = siocgifdevmtu(p, &vlp->vlp_devmtu);
    if (error != 0) {
	printf("vlan_parent_create (%s%d): siocgifdevmtu failed, %d\n",
	       ifnet_name(p), ifnet_unit(p), error);
	FREE(vlp, M_VLAN);
	return (error);
    }
    LIST_INIT(&vlp->vlp_vlan_list);
    vlp->vlp_ifp = p;
    vlp->vlp_retain_count = 1;
    vlp->vlp_signature = VLP_SIGNATURE;
    if (ifnet_offload(p)
	& (IF_HWASSIST_VLAN_MTU | IF_HWASSIST_VLAN_TAGGING)) {
	vlan_parent_flags_set_supports_vlan_mtu(vlp);
    }
    *ret_vlp = vlp;
    return (0);
}

static void
vlan_parent_remove_all_vlans(struct ifnet * p)
{
    ifvlan_ref 		ifv;
    int			need_vlp_release = 0;
    ifvlan_ref		next;
    vlan_parent_ref	vlp;

    vlan_lock();
    vlp = parent_list_lookup(p);
    if (vlp == NULL || vlan_parent_flags_detaching(vlp)) {
	/* no VLAN's */
	vlan_unlock();
	return;
    }
    vlan_parent_flags_set_detaching(vlp);
    vlan_parent_retain(vlp);
    vlan_parent_wait(vlp, "vlan_parent_remove_all_vlans");
    need_vlp_release++;
    vlp = parent_list_lookup(p);
    /* check again */
    if (vlp == NULL) {
	goto signal_done;
    }

    for (ifv = LIST_FIRST(&vlp->vlp_vlan_list); ifv != NULL; ifv = next) {
	struct ifnet *	ifp = ifv->ifv_ifp;
	int		removed;

	next = LIST_NEXT(ifv, ifv_vlan_list);
	removed = vlan_remove(ifv, FALSE);
	if (removed) {
	    vlan_unlock();
	    ifnet_detach(ifp);
	    vlan_lock();
	}
    }

    /* the vlan parent has no more VLAN's */
    ifnet_set_eflags(p, 0, IFEF_VLAN); /* clear IFEF_VLAN */

    LIST_REMOVE(vlp, vlp_parent_list);
    need_vlp_release++;	/* one for being in the list */
    need_vlp_release++; /* final reference */

 signal_done:
    vlan_parent_signal(vlp, "vlan_parent_remove_all_vlans");
    vlan_unlock();

    while (need_vlp_release--) {
	vlan_parent_release(vlp);
    }
    return;
}

static __inline__ int
vlan_parent_no_vlans(vlan_parent_ref vlp)
{
    return (LIST_EMPTY(&vlp->vlp_vlan_list));
}

static void
vlan_parent_add_vlan(vlan_parent_ref vlp, ifvlan_ref ifv, int tag)
{
    LIST_INSERT_HEAD(&vlp->vlp_vlan_list, ifv, ifv_vlan_list);
    ifv->ifv_vlp = vlp;
    ifv->ifv_tag = tag;
    return;
}

static void
vlan_parent_remove_vlan(__unused vlan_parent_ref vlp, ifvlan_ref ifv)
{
    ifv->ifv_vlp = NULL;
    LIST_REMOVE(ifv, ifv_vlan_list);
    return;
}

static int
vlan_clone_attach(void)
{
    int error;

    error = if_clone_attach(&vlan_cloner);
    if (error != 0)
        return error;
    vlan_lock_init();
    return 0;
}

static int
vlan_clone_create(struct if_clone *ifc, u_int32_t unit, __unused void *params)
{
	int							error;
	ifvlan_ref					ifv;
	ifnet_t						ifp;
	struct ifnet_init_params	vlan_init;
	
	error = vlan_globals_init();
	if (error != 0) {
		return (error);
	}
	ifv = _MALLOC(sizeof(struct ifvlan), M_VLAN, M_WAITOK);
	if (ifv == NULL)
		return ENOBUFS;
	bzero(ifv, sizeof(struct ifvlan));
	ifv->ifv_retain_count = 1;
	ifv->ifv_signature = IFV_SIGNATURE;
	multicast_list_init(&ifv->ifv_multicast);
	
	/* use the interface name as the unique id for ifp recycle */
	if ((unsigned int)
	    snprintf(ifv->ifv_name, sizeof(ifv->ifv_name), "%s%d",
		     ifc->ifc_name, unit) >= sizeof(ifv->ifv_name)) {
	    ifvlan_release(ifv);
	    return (EINVAL);
	}
	
	bzero(&vlan_init, sizeof(vlan_init));
	vlan_init.uniqueid = ifv->ifv_name;
	vlan_init.uniqueid_len = strlen(ifv->ifv_name);
	vlan_init.name = ifc->ifc_name;
	vlan_init.unit = unit;
	vlan_init.family = IFNET_FAMILY_VLAN;
	vlan_init.type = IFT_L2VLAN;
	vlan_init.output = vlan_output;
	vlan_init.demux = ether_demux;
	vlan_init.add_proto = ether_add_proto;
	vlan_init.del_proto = ether_del_proto;
	vlan_init.check_multi = ether_check_multi;
	vlan_init.framer = ether_frameout;
	vlan_init.softc = ifv;
	vlan_init.ioctl = vlan_ioctl;
	vlan_init.set_bpf_tap = vlan_set_bpf_tap;
	vlan_init.detach = vlan_if_free;
	vlan_init.broadcast_addr = etherbroadcastaddr;
	vlan_init.broadcast_len = ETHER_ADDR_LEN;
	error = ifnet_allocate(&vlan_init, &ifp);
	
	if (error) {
	    ifvlan_release(ifv);
	    return (error);
	}
	
	ifnet_set_offload(ifp, 0);
	ifnet_set_addrlen(ifp, ETHER_ADDR_LEN); /* XXX ethernet specific */
	ifnet_set_baudrate(ifp, 0);
	ifnet_set_hdrlen(ifp, ETHER_VLAN_ENCAP_LEN);
	
	error = ifnet_attach(ifp, NULL);
	if (error) {
	    ifnet_release(ifp);
	    ifvlan_release(ifv);
	    return (error);
	}
	ifv->ifv_ifp = ifp;
	
	/* attach as ethernet */
	bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
	return (0);
}

static int
vlan_remove(ifvlan_ref ifv, int need_to_wait)
{
    vlan_assert_lock_held();
    if (ifvlan_flags_detaching(ifv)) {
	return (0);
    }
    ifvlan_flags_set_detaching(ifv);
    vlan_unconfig(ifv, need_to_wait);
    return (1);
}


static int
vlan_clone_destroy(struct ifnet *ifp)
{
    ifvlan_ref ifv;

    vlan_lock();
    ifv = ifnet_get_ifvlan_retained(ifp);
    if (ifv == NULL) {
	vlan_unlock();
	return 0;
    }
    if (vlan_remove(ifv, TRUE) == 0) {
	vlan_unlock();
	ifvlan_release(ifv);
	return 0;
    }
    vlan_unlock();
    ifvlan_release(ifv);
    ifnet_detach(ifp);

    return 0;
}

static int 
vlan_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode, bpf_packet_func func)
{
    ifvlan_ref	ifv;

    vlan_lock();
    ifv = ifnet_get_ifvlan_retained(ifp);
    if (ifv == NULL) {
	vlan_unlock();
	return (ENODEV);
    }
    switch (mode) {
        case BPF_TAP_DISABLE:
            ifv->ifv_bpf_input = ifv->ifv_bpf_output = NULL;
            break;

        case BPF_TAP_INPUT:
            ifv->ifv_bpf_input = func;
            break;

        case BPF_TAP_OUTPUT:
	    ifv->ifv_bpf_output = func;
            break;
        
        case BPF_TAP_INPUT_OUTPUT:
            ifv->ifv_bpf_input = ifv->ifv_bpf_output = func;
            break;
        default:
            break;
    }
    vlan_unlock();
    ifvlan_release(ifv);
    return 0;
}

static int
vlan_output(struct ifnet * ifp, struct mbuf * m)
{
    bpf_packet_func 		bpf_func;
    struct ether_vlan_header *	evl;
    int				encaplen;
    ifvlan_ref			ifv;
    struct ifnet *		p;
    int 			soft_vlan;
    u_short			tag;
    vlan_parent_ref		vlp = NULL;
    int				err;
    struct flowadv		adv = { FADV_SUCCESS };
	
    if (m == 0) {
	return (0);
    }
    if ((m->m_flags & M_PKTHDR) == 0) {
	m_freem_list(m);
	return (0);
    }
    vlan_lock();
    ifv = ifnet_get_ifvlan_retained(ifp);
    if (ifv == NULL || ifvlan_flags_ready(ifv) == 0) {
	goto unlock_done;
    }
    vlp = ifvlan_get_vlan_parent_retained(ifv);
    if (vlp == NULL) {
	goto unlock_done;
    }
    p = vlp->vlp_ifp;
    (void)ifnet_stat_increment_out(ifp, 1, m->m_pkthdr.len, 0);
    soft_vlan = (ifnet_offload(p) & IF_HWASSIST_VLAN_TAGGING) == 0;
    bpf_func = ifv->ifv_bpf_output;
    tag = ifv->ifv_tag;
    encaplen = ifv->ifv_encaplen;
    vlan_unlock();

    ifvlan_release(ifv);
    vlan_parent_release(vlp);

    vlan_bpf_output(ifp, m, bpf_func);
	
    /* do not run parent's if_output() if the parent is not up */
    if ((ifnet_flags(p) & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
	m_freem(m);
	atomic_add_64(&ifp->if_collisions, 1);
	return (0);
    }
    /*
     * If underlying interface can do VLAN tag insertion itself,
     * just pass the packet along. However, we need some way to
     * tell the interface where the packet came from so that it
     * knows how to find the VLAN tag to use.  We use a field in
     * the mbuf header to store the VLAN tag, and a bit in the
     * csum_flags field to mark the field as valid.
     */
    if (soft_vlan == 0) {
	m->m_pkthdr.csum_flags |= CSUM_VLAN_TAG_VALID;
	m->m_pkthdr.vlan_tag = tag;
    } else {
	M_PREPEND(m, encaplen, M_DONTWAIT);
	if (m == NULL) {
	    printf("%s%d: unable to prepend VLAN header\n", ifnet_name(ifp),
		   ifnet_unit(ifp));
	    atomic_add_64(&ifp->if_oerrors, 1);
	    return (0);
	}
	/* M_PREPEND takes care of m_len, m_pkthdr.len for us */
	if (m->m_len < (int)sizeof(*evl)) {
	    m = m_pullup(m, sizeof(*evl));
	    if (m == NULL) {
		printf("%s%d: unable to pullup VLAN header\n", ifnet_name(ifp),
		       ifnet_unit(ifp));
		atomic_add_64(&ifp->if_oerrors, 1);
		return (0);
	    }
	}
		
	/*
	 * Transform the Ethernet header into an Ethernet header
	 * with 802.1Q encapsulation.
	 */
	bcopy(mtod(m, char *) + encaplen,
	      mtod(m, char *), ETHER_HDR_LEN);
	evl = mtod(m, struct ether_vlan_header *);
	evl->evl_proto = evl->evl_encap_proto;
	evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
	evl->evl_tag = htons(tag);
    }

    err = dlil_output(p, PF_VLAN, m, NULL, NULL, 1, &adv);

    if (err == 0) {
	if (adv.code == FADV_FLOW_CONTROLLED) {
	    err = EQFULL;
	} else if (adv.code == FADV_SUSPENDED) {
	    err = EQSUSPENDED;
	}
    }

    return (err);

 unlock_done:
    vlan_unlock();
    if (ifv != NULL) {
	ifvlan_release(ifv);
    }
    if (vlp != NULL) {
	vlan_parent_release(vlp);
    }
    m_freem_list(m);
    return (0);

}

static int
vlan_input(ifnet_t p, __unused protocol_family_t protocol,
					   mbuf_t m, char *frame_header)
{
    bpf_packet_func 		bpf_func = NULL;
    struct ether_vlan_header *	evl;
    struct ifnet *		ifp = NULL;
    int 			soft_vlan = 0;
    u_int 			tag = 0;

    if (m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) {
	/*
	 * Packet is tagged, m contains a normal
	 * Ethernet frame; the tag is stored out-of-band.
	 */
	m->m_pkthdr.csum_flags &= ~CSUM_VLAN_TAG_VALID;
	tag = EVL_VLANOFTAG(m->m_pkthdr.vlan_tag);
	m->m_pkthdr.vlan_tag = 0;
    } else {
	soft_vlan = 1;
	switch (ifnet_type(p)) {
	case IFT_ETHER:
	    if (m->m_len < ETHER_VLAN_ENCAP_LEN) {
		m_freem(m);
		return 0;
	    }
	    evl = (struct ether_vlan_header *)(void *)frame_header;
	    if (ntohs(evl->evl_proto) == ETHERTYPE_VLAN) {
		/* don't allow VLAN within VLAN */
		m_freem(m);
		return (0);
	    }
	    tag = EVL_VLANOFTAG(ntohs(evl->evl_tag));
		
	    /*
	     * Restore the original ethertype.  We'll remove
	     * the encapsulation after we've found the vlan
	     * interface corresponding to the tag.
	     */
	    evl->evl_encap_proto = evl->evl_proto;
	    break;
	default:
	    printf("vlan_demux: unsupported if type %u", 
		   ifnet_type(p));
	    m_freem(m);
	    return 0;
	    break;
	}
    }
    if (tag != 0) {
	ifvlan_ref		ifv;

	if ((ifnet_eflags(p) & IFEF_VLAN) == 0) {
	    /* don't bother looking through the VLAN list */
	    m_freem(m);
	    return 0;
	}
	vlan_lock();
	ifv = vlan_lookup_parent_and_tag(p, tag);
	if (ifv != NULL) {
	    ifp = ifv->ifv_ifp;
	}
	if (ifv == NULL 
	    || ifvlan_flags_ready(ifv) == 0
	    || (ifnet_flags(ifp) & IFF_UP) == 0) {
	    vlan_unlock();
	    m_freem(m);
	    return 0;
	}
	bpf_func = ifv->ifv_bpf_input;
	vlan_unlock();
    }
    if (soft_vlan) {
	/*
	 * Packet had an in-line encapsulation header;
	 * remove it.  The original header has already
	 * been fixed up above.
	 */
	m->m_len -= ETHER_VLAN_ENCAP_LEN;
	m->m_data += ETHER_VLAN_ENCAP_LEN;
	m->m_pkthdr.len -= ETHER_VLAN_ENCAP_LEN;
	m->m_pkthdr.csum_flags = 0; /* can't trust hardware checksum */
    }
    if (tag != 0) {
	m->m_pkthdr.rcvif = ifp;
	m->m_pkthdr.header = frame_header;
	(void)ifnet_stat_increment_in(ifp, 1, 
				      m->m_pkthdr.len + ETHER_HDR_LEN, 0);
	vlan_bpf_input(ifp, m, bpf_func, frame_header, ETHER_HDR_LEN, 
		       soft_vlan ? ETHER_VLAN_ENCAP_LEN : 0);
	/* We found a vlan interface, inject on that interface. */
	dlil_input_packet_list(ifp, m);
    } else {
	m->m_pkthdr.header = frame_header;
	/* Send priority-tagged packet up through the parent */
	dlil_input_packet_list(p, m);
    }
    return 0;
}

static int
vlan_config(struct ifnet * ifp, struct ifnet * p, int tag)
{
    int			error;
    int			first_vlan = FALSE;
    ifvlan_ref 		ifv = NULL;
    int			ifv_added = FALSE;
    int			need_vlp_release = 0;
    vlan_parent_ref	new_vlp = NULL;
    ifnet_offload_t	offload;
    u_int16_t		parent_flags;
    vlan_parent_ref	vlp = NULL;

    /* pre-allocate space for vlan_parent, in case we're first */
    error = vlan_parent_create(p, &new_vlp);
    if (error != 0) {
	return (error);
    }

    vlan_lock();
    ifv = ifnet_get_ifvlan_retained(ifp);
    if (ifv == NULL || ifv->ifv_vlp != NULL) {
	vlan_unlock();
	if (ifv != NULL) {
	    ifvlan_release(ifv);
	}
	vlan_parent_release(new_vlp);
	return (EBUSY);
    }
    vlp = parent_list_lookup(p);
    if (vlp != NULL) {
	vlan_parent_retain(vlp);
	need_vlp_release++;
	if (vlan_parent_lookup_tag(vlp, tag) != NULL) {
	    /* already a VLAN with that tag on this interface */
	    error = EADDRINUSE;
	    goto unlock_done;
	}
    }
    else {
	/* one for being in the list */
	vlan_parent_retain(new_vlp);

	/* we're the first VLAN on this interface */
	LIST_INSERT_HEAD(&g_vlan->parent_list, new_vlp, vlp_parent_list);
	vlp = new_vlp;

	vlan_parent_retain(vlp);
	need_vlp_release++;
    }

    /* need to wait to ensure no one else is trying to add/remove */
    vlan_parent_wait(vlp, "vlan_config");

    if (ifnet_get_ifvlan(ifp) != ifv) {
	error = EINVAL;
	goto signal_done;
    }

    /* check again because someone might have gotten in */
    if (parent_list_lookup(p) != vlp) {
	error = EBUSY;
	goto signal_done;
    }

    if (vlan_parent_flags_detaching(vlp)
	|| ifvlan_flags_detaching(ifv) || ifv->ifv_vlp != NULL) {
	error = EBUSY;
	goto signal_done;
    }

    /* check again because someone might have gotten the tag */
    if (vlan_parent_lookup_tag(vlp, tag) != NULL) {
	/* already a VLAN with that tag on this interface */
	error = EADDRINUSE;
	goto signal_done;
    }

    if (vlan_parent_no_vlans(vlp)) {
	first_vlan = TRUE;
    }
    vlan_parent_add_vlan(vlp, ifv, tag);
    ifvlan_retain(ifv);	/* parent references ifv */
    ifv_added = TRUE;

    /* check whether bond interface is using parent interface */
    ifnet_lock_exclusive(p);
    if ((ifnet_eflags(p) & IFEF_BOND) != 0) {
	ifnet_lock_done(p);
	/* don't allow VLAN over interface that's already part of a bond */
	error = EBUSY;
	goto signal_done;
    }
    /* prevent BOND interface from using it */
    /* Can't use ifnet_set_eflags because that would take the lock */
    p->if_eflags |= IFEF_VLAN;
    ifnet_lock_done(p);
    vlan_unlock();

    if (first_vlan) {
	/* attach our VLAN "protocol" to the interface */
	error = vlan_attach_protocol(p);
	if (error) {
	    vlan_lock();
	    goto signal_done;
	}
    }

    /* configure parent to receive our multicast addresses */
    error = multicast_list_program(&ifv->ifv_multicast, ifp, p);
    if (error != 0) {
	if (first_vlan) {
	    (void)vlan_detach_protocol(p);
	}
	vlan_lock();
	goto signal_done;
    }

    /* set our ethernet address to that of the parent */
    ifnet_set_lladdr_and_type(ifp, ifnet_lladdr(p), ETHER_ADDR_LEN, IFT_ETHER);

    /* no failures past this point */
    vlan_lock();

    ifv->ifv_encaplen = ETHER_VLAN_ENCAP_LEN;
    ifv->ifv_flags = 0;
    if (vlan_parent_flags_supports_vlan_mtu(vlp)) {
	ifv->ifv_mtufudge = 0;
    } else {
	/*
	 * Fudge the MTU by the encapsulation size.  This
	 * makes us incompatible with strictly compliant
	 * 802.1Q implementations, but allows us to use
	 * the feature with other NetBSD implementations,
	 * which might still be useful.
	 */
	ifv->ifv_mtufudge = ifv->ifv_encaplen;
    }
    ifnet_set_mtu(ifp, ETHERMTU - ifv->ifv_mtufudge);

    /*
     * Copy only a selected subset of flags from the parent.
     * Other flags are none of our business.
     */
    parent_flags = ifnet_flags(p) 
	& (IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX);
    ifnet_set_flags(ifp, parent_flags,
		    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX);

    /* use hwassist bits from parent interface, but exclude VLAN bits */
    offload = ifnet_offload(p) & ~(IFNET_VLAN_TAGGING | IFNET_VLAN_MTU);
    ifnet_set_offload(ifp, offload);

    ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);
    ifvlan_flags_set_ready(ifv);
    vlan_parent_signal(vlp, "vlan_config");
    vlan_unlock();
    if (new_vlp != vlp) {
	/* throw it away, it wasn't needed */
	vlan_parent_release(new_vlp);
    }
    if (ifv != NULL) {
	ifvlan_release(ifv);
    }
    if (first_vlan) {
	/* mark the parent interface up */
	ifnet_set_flags(p, IFF_UP, IFF_UP);
	(void)ifnet_ioctl(p, 0, SIOCSIFFLAGS, (caddr_t)NULL);
    }
    return 0;

 signal_done:
    vlan_assert_lock_held();

    if (ifv_added) {
	vlan_parent_remove_vlan(vlp, ifv);
	if (!vlan_parent_flags_detaching(vlp) && vlan_parent_no_vlans(vlp)) {
	    /* the vlan parent has no more VLAN's */
	    ifnet_set_eflags(p, 0, IFEF_VLAN);
	    LIST_REMOVE(vlp, vlp_parent_list);
	    /* release outside of the lock below */
	    need_vlp_release++;

	    /* one for being in the list */
	    need_vlp_release++;
	}
    }
    vlan_parent_signal(vlp, "vlan_config");

 unlock_done:
    vlan_unlock();

    while (need_vlp_release--) {
	vlan_parent_release(vlp);
    }
    if (new_vlp != vlp) {
	vlan_parent_release(new_vlp);
    }
    if (ifv != NULL) {
	if (ifv_added) {
	    ifvlan_release(ifv);
	}
	ifvlan_release(ifv);
    }
    return (error);
}

static void
vlan_link_event(struct ifnet * ifp, struct ifnet * p)
{
    struct ifmediareq ifmr;

    /* generate a link event based on the state of the underlying interface */
    bzero(&ifmr, sizeof(ifmr));
    snprintf(ifmr.ifm_name, sizeof(ifmr.ifm_name),
	     "%s%d", ifnet_name(p), ifnet_unit(p));
    if (ifnet_ioctl(p, 0, SIOCGIFMEDIA, &ifmr) == 0
	&& ifmr.ifm_count > 0 && ifmr.ifm_status & IFM_AVALID) {
	u_int32_t	event;
	
	event = (ifmr.ifm_status & IFM_ACTIVE)
	    ? KEV_DL_LINK_ON : KEV_DL_LINK_OFF;
	interface_link_event(ifp, event);
    }
    return;
}

static int
vlan_unconfig(ifvlan_ref ifv, int need_to_wait)
{
    struct ifnet *	ifp = ifv->ifv_ifp;
    int			last_vlan = FALSE;
    int			need_ifv_release = 0;
    int			need_vlp_release = 0;
    struct ifnet *	p;
    vlan_parent_ref	vlp;

    vlan_assert_lock_held();
    vlp = ifv->ifv_vlp;
    if (vlp == NULL) {
	return (0);
    }
    if (need_to_wait) {
	need_vlp_release++;
	vlan_parent_retain(vlp);
	vlan_parent_wait(vlp, "vlan_unconfig");

        /* check again because another thread could be in vlan_unconfig */
	if (ifv != ifnet_get_ifvlan(ifp)) {
	    goto signal_done;
	}
	if (ifv->ifv_vlp != vlp) {
	    /* vlan parent changed */
	    goto signal_done;
	}
    }

    /* ifv has a reference on vlp, need to remove it */
    need_vlp_release++;
    p = vlp->vlp_ifp;

    /* remember whether we're the last VLAN on the parent */
    if (LIST_NEXT(LIST_FIRST(&vlp->vlp_vlan_list), ifv_vlan_list) == NULL) {
	if (g_vlan->verbose) {
	    printf("vlan_unconfig: last vlan on %s%d\n",
		   ifnet_name(p), ifnet_unit(p));
	}
	last_vlan = TRUE;
    }

    /* back-out any effect our mtu might have had on the parent */
    (void)ifvlan_new_mtu(ifv, ETHERMTU - ifv->ifv_mtufudge);

    vlan_unlock();

    /* un-join multicast on parent interface */
    (void)multicast_list_remove(&ifv->ifv_multicast);

    /* Clear our MAC address. */
    ifnet_set_lladdr_and_type(ifp, NULL, 0, IFT_L2VLAN);

    /* detach VLAN "protocol" */
    if (last_vlan) {
	(void)vlan_detach_protocol(p);
    }

    vlan_lock();

    /* return to the state we were in before SIFVLAN */
    ifnet_set_mtu(ifp, 0);
    ifnet_set_flags(ifp, 0, 
		    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX | IFF_RUNNING);
    ifnet_set_offload(ifp, 0);
    ifv->ifv_mtufudge = 0;

    /* Disconnect from parent. */
    vlan_parent_remove_vlan(vlp, ifv);
    ifv->ifv_flags = 0;

    /* vlan_parent has reference to ifv, remove it */
    need_ifv_release++;

    /* from this point on, no more referencing ifv */
    if (last_vlan && !vlan_parent_flags_detaching(vlp)) {
	/* the vlan parent has no more VLAN's */
	ifnet_set_eflags(p, 0, IFEF_VLAN);
	LIST_REMOVE(vlp, vlp_parent_list);

	/* one for being in the list */
	need_vlp_release++;

	/* release outside of the lock below */
	need_vlp_release++;
    }

 signal_done:
    if (need_to_wait) {
	vlan_parent_signal(vlp, "vlan_unconfig");
    }
    vlan_unlock();
    while (need_ifv_release--) {
	ifvlan_release(ifv);
    }
    while (need_vlp_release--) {	/* references to vlp */
	vlan_parent_release(vlp);
    }
    vlan_lock();
    return (0);
}

static int
vlan_set_promisc(struct ifnet * ifp)
{
    int 			error = 0;
    ifvlan_ref			ifv;
    vlan_parent_ref		vlp;

    vlan_lock();
    ifv = ifnet_get_ifvlan_retained(ifp);
    if (ifv == NULL) {
	error = EBUSY;
	goto done;
    }

    vlp = ifv->ifv_vlp;
    if (vlp == NULL) {
	goto done;
    }
    if ((ifnet_flags(ifp) & IFF_PROMISC) != 0) {
	if (!ifvlan_flags_promisc(ifv)) {
	    error = ifnet_set_promiscuous(vlp->vlp_ifp, 1);
	    if (error == 0) {
		ifvlan_flags_set_promisc(ifv);
	    }
	}
    } else {
	if (ifvlan_flags_promisc(ifv)) {
	    error = ifnet_set_promiscuous(vlp->vlp_ifp, 0);
	    if (error == 0) {
		ifvlan_flags_clear_promisc(ifv);
	    }
	}
    }
 done:
    vlan_unlock();
    if (ifv != NULL) {
	ifvlan_release(ifv);
    }
    return (error);
}

static int
ifvlan_new_mtu(ifvlan_ref ifv, int mtu)
{
    struct ifdevmtu *	devmtu_p;
    int			error = 0;
    struct ifnet * 	ifp = ifv->ifv_ifp;
    int			max_mtu;
    int			new_mtu = 0;
    int			req_mtu;
    vlan_parent_ref	vlp;

    vlan_assert_lock_held();
    vlp = ifv->ifv_vlp;
    devmtu_p = &vlp->vlp_devmtu;
    req_mtu = mtu + ifv->ifv_mtufudge;
    if (req_mtu > devmtu_p->ifdm_max || req_mtu < devmtu_p->ifdm_min) {
	return (EINVAL);
    }
    max_mtu = vlan_parent_find_max_mtu(vlp, ifv);
    if (req_mtu > max_mtu) {
	new_mtu = req_mtu;
    }
    else if (max_mtu < devmtu_p->ifdm_current) {
	new_mtu = max_mtu;
    }
    if (new_mtu != 0) {
	struct ifnet * 	p = vlp->vlp_ifp;
	vlan_unlock();
	error = siocsifaltmtu(p, new_mtu);
	vlan_lock();
    }
    if (error == 0) {
	if (new_mtu != 0) {
	    devmtu_p->ifdm_current = new_mtu;
	}
	ifnet_set_mtu(ifp, mtu);
    }
    return (error);
}

static int
vlan_set_mtu(struct ifnet * ifp, int mtu)
{
    int			error = 0;
    ifvlan_ref		ifv;
    vlan_parent_ref	vlp;

    if (mtu < IF_MINMTU) {
	return (EINVAL);
    }
    vlan_lock();
    ifv = ifnet_get_ifvlan_retained(ifp);
    if (ifv == NULL) {
	vlan_unlock();
	return (EBUSY);
    }
    vlp = ifvlan_get_vlan_parent_retained(ifv);
    if (vlp == NULL) {
	vlan_unlock();
	ifvlan_release(ifv);
	if (mtu != 0) {
	    return (EINVAL);
	}
	return (0);
    }
    vlan_parent_wait(vlp, "vlan_set_mtu");

    /* check again, something might have changed */
    if (ifnet_get_ifvlan(ifp) != ifv
	|| ifvlan_flags_detaching(ifv)) {
	error = EBUSY;
	goto signal_done;
    }
    if (ifv->ifv_vlp != vlp) {
	/* vlan parent changed */
	goto signal_done;
    }
    if (vlan_parent_flags_detaching(vlp)) {
	if (mtu != 0) {
	    error = EINVAL;
	}
	goto signal_done;
    }
    error = ifvlan_new_mtu(ifv, mtu);

 signal_done:
    vlan_parent_signal(vlp, "vlan_set_mtu");
    vlan_unlock();
    vlan_parent_release(vlp);
    ifvlan_release(ifv);

    return (error);
}

static int
vlan_ioctl(ifnet_t ifp, u_long cmd, void * data)
{
    struct ifdevmtu *	devmtu_p;
    int 		error = 0;
    struct ifaddr *	ifa;
    struct ifmediareq	*ifmr;
    struct ifreq *	ifr;
    ifvlan_ref		ifv;
    struct ifnet *	p;
    u_short		tag;
    user_addr_t		user_addr;
    vlan_parent_ref	vlp;
    struct vlanreq 	vlr;

    if (ifnet_type(ifp) != IFT_L2VLAN) {
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
	vlan_lock();
	ifv = (ifvlan_ref)ifnet_softc(ifp);
	if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	    vlan_unlock();
	    return (ifv == NULL ? EOPNOTSUPP : EBUSY);
	}
	p = (ifv->ifv_vlp == NULL) ? NULL : ifv->ifv_vlp->vlp_ifp;
	vlan_unlock();
	ifmr = (struct ifmediareq *)data;
	user_addr =  (cmd == SIOCGIFMEDIA64) ?
	    ((struct ifmediareq64 *)ifmr)->ifmu_ulist :
	    CAST_USER_ADDR_T(((struct ifmediareq32 *)ifmr)->ifmu_ulist);
	if (p != NULL) {
	    struct ifmediareq p_ifmr;

	    bzero(&p_ifmr, sizeof(p_ifmr));
	    error = ifnet_ioctl(p, 0, SIOCGIFMEDIA, &p_ifmr);
	    if (error == 0) {
		ifmr->ifm_active = p_ifmr.ifm_active;
		ifmr->ifm_current = p_ifmr.ifm_current;
		ifmr->ifm_mask = p_ifmr.ifm_mask;
		ifmr->ifm_status = p_ifmr.ifm_status;
		ifmr->ifm_count = p_ifmr.ifm_count;
		/* Limit the result to the parent's current config. */
		if (ifmr->ifm_count >= 1 && user_addr != USER_ADDR_NULL) {
		    ifmr->ifm_count = 1;
		    error = copyout(&ifmr->ifm_current, user_addr, 
				    sizeof(int));
		}
	    }
	} else {
	    ifmr->ifm_active = ifmr->ifm_current = IFM_NONE;
	    ifmr->ifm_mask = 0;
	    ifmr->ifm_status = IFM_AVALID;
	    ifmr->ifm_count = 1;
	    if (user_addr != USER_ADDR_NULL) {
		error = copyout(&ifmr->ifm_current, user_addr, sizeof(int));
	    }
	}
	break;

    case SIOCSIFMEDIA:
	error = EOPNOTSUPP;
	break;

    case SIOCGIFDEVMTU:
	vlan_lock();
	ifv = (ifvlan_ref)ifnet_softc(ifp);
	if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	    vlan_unlock();
	    return (ifv == NULL ? EOPNOTSUPP : EBUSY);
	}
	vlp = ifv->ifv_vlp;
	if (vlp != NULL) {
	    int		min_mtu = vlp->vlp_devmtu.ifdm_min - ifv->ifv_mtufudge;
	    devmtu_p = &ifr->ifr_devmtu;
	    devmtu_p->ifdm_current = ifnet_mtu(ifp);
	    devmtu_p->ifdm_min = max(min_mtu, IF_MINMTU);
	    devmtu_p->ifdm_max = vlp->vlp_devmtu.ifdm_max - ifv->ifv_mtufudge;
	}
	else {
	    devmtu_p = &ifr->ifr_devmtu;
	    devmtu_p->ifdm_current = 0;
	    devmtu_p->ifdm_min = 0;
	    devmtu_p->ifdm_max = 0;
	}
	vlan_unlock();
	break;

    case SIOCSIFMTU:
	error = vlan_set_mtu(ifp, ifr->ifr_mtu);
	break;

    case SIOCSIFVLAN:
	user_addr = proc_is64bit(current_proc()) 
	    ? ifr->ifr_data64 : CAST_USER_ADDR_T(ifr->ifr_data);
	error = copyin(user_addr, &vlr, sizeof(vlr));
	if (error) {
	    break;
	}
	p = NULL;
	if (vlr.vlr_parent[0] != '\0') {
	    if (vlr.vlr_tag & ~EVL_VLID_MASK) {
		/*
		 * Don't let the caller set up a VLAN tag with
		 * anything except VLID bits.
		 */
		error = EINVAL;
		break;
	    }
	    p = ifunit(vlr.vlr_parent);
	    if (p == NULL) {
		error = ENXIO;
		break;
	    }
	    /* can't do VLAN over anything but ethernet or ethernet aggregate */
	    if (ifnet_type(p) != IFT_ETHER 
		&& ifnet_type(p) != IFT_IEEE8023ADLAG) {
		error = EPROTONOSUPPORT;
		break;
	    }
	    error = vlan_config(ifp, p, vlr.vlr_tag);
	    if (error) {
		break;
	    }
	    
	    /* Update promiscuous mode, if necessary. */
	    (void)vlan_set_promisc(ifp);
	    
	    /* generate a link event based on the state of the parent */
	    vlan_link_event(ifp, p);
	} 
	else {
	    int		need_link_event = FALSE;

	    vlan_lock();
	    ifv = (ifvlan_ref)ifnet_softc(ifp);
	    if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
		vlan_unlock();
		error = (ifv == NULL ? EOPNOTSUPP : EBUSY);
		break;
	    }
	    need_link_event = vlan_remove(ifv, TRUE);
	    vlan_unlock();
	    if (need_link_event) {
		interface_link_event(ifp, KEV_DL_LINK_OFF);
	    }
	}
	break;
		
    case SIOCGIFVLAN:
	bzero(&vlr, sizeof vlr);
	vlan_lock();
	ifv = (ifvlan_ref)ifnet_softc(ifp);
	if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	    vlan_unlock();
	    return (ifv == NULL ? EOPNOTSUPP : EBUSY);
	}
	p = (ifv->ifv_vlp == NULL) ? NULL : ifv->ifv_vlp->vlp_ifp;
	tag = ifv->ifv_tag;
	vlan_unlock();
	if (p != NULL) {
	    snprintf(vlr.vlr_parent, sizeof(vlr.vlr_parent),
		     "%s%d", ifnet_name(p), ifnet_unit(p));
	    vlr.vlr_tag = tag;
	}
	user_addr = proc_is64bit(current_proc()) 
	    ? ifr->ifr_data64 : CAST_USER_ADDR_T(ifr->ifr_data);
	error = copyout(&vlr, user_addr, sizeof(vlr));
	break;
		
    case SIOCSIFFLAGS:
	/*
	 * For promiscuous mode, we enable promiscuous mode on
	 * the parent if we need promiscuous on the VLAN interface.
	 */
	error = vlan_set_promisc(ifp);
	break;

    case SIOCADDMULTI:
    case SIOCDELMULTI:
	error = vlan_setmulti(ifp);
	break;
    default:
	error = EOPNOTSUPP;
    }
    return error;
}

static void 
vlan_if_free(struct ifnet * ifp)
{
    ifvlan_ref	ifv;

    if (ifp == NULL) {
	return;
    }
    ifv = (ifvlan_ref)ifnet_softc(ifp);
    if (ifv == NULL) {
	return;
    }
    ifvlan_release(ifv);
    ifnet_release(ifp);
    return;
}

static void
vlan_event(struct ifnet	* p, __unused protocol_family_t protocol,
		   const struct kev_msg * event)
{
    int			event_code;

    /* Check if the interface we are attached to is being detached */
    if (event->vendor_code != KEV_VENDOR_APPLE
	|| event->kev_class != KEV_NETWORK_CLASS
	|| event->kev_subclass != KEV_DL_SUBCLASS) {
	return;
    }
    event_code = event->event_code;
    switch (event_code) {
    case KEV_DL_LINK_OFF:
    case KEV_DL_LINK_ON:
	vlan_parent_link_event(p, event_code);
	break;
    default:
	return;
    }
    return;
}

static errno_t
vlan_detached(ifnet_t p, __unused protocol_family_t protocol)
{
    if (ifnet_is_attached(p, 0) == 0) {
	/* if the parent isn't attached, remove all VLANs */
	vlan_parent_remove_all_vlans(p);
    }
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
    strncpy(event.if_name, ifnet_name(ifp), IFNAMSIZ);
    ifnet_event(ifp, &event.header);
    return;
}

static void
vlan_parent_link_event(struct ifnet * p, u_int32_t event_code)
{
    ifvlan_ref 		ifv;
    vlan_parent_ref 	vlp;

    vlan_lock();
    if ((ifnet_eflags(p) & IFEF_VLAN) == 0) {
	vlan_unlock();
	/* no VLAN's */
	return;
    }
    vlp = parent_list_lookup(p);
    if (vlp == NULL) {
	/* no VLAN's */
	vlan_unlock();
	return;
    }

    vlan_parent_retain(vlp);
    vlan_parent_wait(vlp, "vlan_parent_link_event");
    if (vlan_parent_flags_detaching(vlp)) {
	goto signal_done;
    }

    vlan_unlock();

    /* vlan_parent_wait() gives us exclusive access to the list */
    LIST_FOREACH(ifv, &vlp->vlp_vlan_list, ifv_vlan_list) {
	struct ifnet *	ifp = ifv->ifv_ifp;

	interface_link_event(ifp, event_code);
    }

    vlan_lock();

 signal_done:
    vlan_parent_signal(vlp, "vlan_parent_link_event");
    vlan_unlock();
    vlan_parent_release(vlp);
    return;

}

/*
 * Function: vlan_attach_protocol
 * Purpose:
 *   Attach a DLIL protocol to the interface, using the ETHERTYPE_VLAN
 *   demux ether type.
 *
 *	 The ethernet demux actually special cases VLAN to support hardware.
 *	 The demux here isn't used. The demux will return PF_VLAN for the
 *	 appropriate packets and our vlan_input function will be called.
 */
static int
vlan_attach_protocol(struct ifnet *ifp)
{
    int								error;
    struct ifnet_attach_proto_param	reg;
	
    bzero(&reg, sizeof(reg));
    reg.input            = vlan_input;
    reg.event            = vlan_event;
    reg.detached         = vlan_detached;
    error = ifnet_attach_protocol(ifp, PF_VLAN, &reg);
    if (error) {
	printf("vlan_proto_attach(%s%d) ifnet_attach_protocol failed, %d\n",
	       ifnet_name(ifp), ifnet_unit(ifp), error);
    }
    return (error);
}

/*
 * Function: vlan_detach_protocol
 * Purpose:
 *   Detach our DLIL protocol from an interface
 */
static int
vlan_detach_protocol(struct ifnet *ifp)
{
    int         error;

    error = ifnet_detach_protocol(ifp, PF_VLAN);
    if (error) {
	printf("vlan_proto_detach(%s%d) ifnet_detach_protocol failed, %d\n",
	       ifnet_name(ifp), ifnet_unit(ifp), error);
    }
	
    return (error);
}

/*
 * DLIL interface family functions
 *   We use the ethernet plumb functions, since that's all we support.
 *   If we wanted to handle multiple LAN types (tokenring, etc.), we'd
 *   call the appropriate routines for that LAN type instead of hard-coding
 *   ethernet.
 */
static errno_t
vlan_attach_inet(struct ifnet *ifp, protocol_family_t protocol_family)
{
    return (ether_attach_inet(ifp, protocol_family));
}

static void
vlan_detach_inet(struct ifnet *ifp, protocol_family_t protocol_family)
{
    ether_detach_inet(ifp, protocol_family);
}

#if INET6
static errno_t
vlan_attach_inet6(struct ifnet *ifp, protocol_family_t protocol_family)
{
    return (ether_attach_inet6(ifp, protocol_family));
}

static void
vlan_detach_inet6(struct ifnet *ifp, protocol_family_t protocol_family)
{
    ether_detach_inet6(ifp, protocol_family);
}
#endif /* INET6 */

#if NETAT
static errno_t
vlan_attach_at(struct ifnet *ifp, protocol_family_t protocol_family)
{
    return (ether_attach_at(ifp, protocol_family));
}

static void
vlan_detach_at(struct ifnet *ifp, protocol_family_t protocol_family)
{
    ether_detach_at(ifp, protocol_family);
}
#endif /* NETAT */

__private_extern__ int
vlan_family_init(void)
{
    int error=0;

    error = proto_register_plumber(PF_INET, IFNET_FAMILY_VLAN, 
				   vlan_attach_inet, vlan_detach_inet);
    if (error != 0) {
	printf("proto_register_plumber failed for AF_INET error=%d\n",
	       error);
	goto done;
    }
#if INET6
    error = proto_register_plumber(PF_INET6, IFNET_FAMILY_VLAN, 
				   vlan_attach_inet6, vlan_detach_inet6);
    if (error != 0) {
	printf("proto_register_plumber failed for AF_INET6 error=%d\n",
	       error);
	goto done;
    }
#endif
#if NETAT
    error = proto_register_plumber(PF_APPLETALK, IFNET_FAMILY_VLAN, 
				  vlan_attach_at, vlan_detach_at);
    if (error != 0) {
	printf("proto_register_plumber failed for AF_APPLETALK error=%d\n",
	       error);
	goto done;
    }
#endif /* NETAT */
    error = vlan_clone_attach();
    if (error != 0) {
        printf("proto_register_plumber failed vlan_clone_attach error=%d\n",
               error);
        goto done;
    }


 done:
    return (error);
}
