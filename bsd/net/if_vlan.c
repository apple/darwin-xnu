/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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

#include <kern/locks.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/if_ether.h>
#endif

#include <net/if_media.h>
#include <net/multicast_list.h>

#define	IF_MAXUNIT		0x7fff	/* historical value */

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
    lck_grp_attr_setdefault(grp_attrs);
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
    lck_attr_setdefault(lck_attrs);
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

typedef struct vlan_parent {
    LIST_ENTRY(vlan_parent)	vlp_parent_list;/* list of parents */
    struct ifnet *		vlp_ifp;	/* interface */
    struct ifvlan_list		vlp_vlan_list;	/* list of VLAN's */
#define VLPF_SUPPORTS_VLAN_MTU	0x1
#define VLPF_CHANGE_IN_PROGRESS	0x2
#define VLPF_DETACHING		0x4
    u_int32_t			vlp_flags;
    struct ifdevmtu		vlp_devmtu;
    UInt32			vlp_retain_count;
} vlan_parent, * vlan_parent_ref;

struct ifvlan {
    LIST_ENTRY(ifvlan) 		ifv_vlan_list;
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
SYSCTL_NODE(_net_link, IFT_L2VLAN, vlan, CTLFLAG_RW, 0, "IEEE 802.1Q VLAN");
SYSCTL_NODE(_net_link_vlan, PF_LINK, link, CTLFLAG_RW, 0, "for consistency");
#endif 0

#define M_VLAN 		M_DEVBUF

static	int vlan_clone_create(struct if_clone *, int);
static	void vlan_clone_destroy(struct ifnet *);
static	int vlan_input(struct mbuf *m, char *frame_header, struct ifnet *ifp,
					   u_long protocol_family, int sync_ok);
static	int vlan_output(struct ifnet *ifp, struct mbuf *m);
static	int vlan_ioctl(ifnet_t ifp, u_int32_t cmd, void * addr);
static  int vlan_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode,
			     bpf_packet_func func);
static 	int vlan_attach_protocol(struct ifnet *ifp);
static	int vlan_detach_protocol(struct ifnet *ifp);
static	int vlan_setmulti(struct ifnet *ifp);
static	int vlan_unconfig(struct ifnet *ifp);
static 	int vlan_config(struct ifnet * ifp, struct ifnet * p, int tag);
static	void vlan_if_free(struct ifnet * ifp);
static 	void vlan_remove(ifvlan_ref ifv);
static	void vlan_if_detach(struct ifnet * ifp);
static 	int vlan_new_mtu(struct ifnet * ifp, int mtu);

static struct if_clone vlan_cloner = IF_CLONE_INITIALIZER(VLANNAME,
							  vlan_clone_create, 
							  vlan_clone_destroy, 
							  0, 
							  IF_MAXUNIT);
static	void interface_link_event(struct ifnet * ifp, u_long event_code);
static	void vlan_parent_link_event(vlan_parent_ref vlp, 
				    u_long event_code);
extern int dlil_input_packet(struct ifnet  *ifp, struct mbuf *m, char *frame_header);

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
    error = dlil_ioctl(0, ifp, SIOCGIFDEVMTU, (caddr_t)&ifr);
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
    return (dlil_ioctl(0, ifp, SIOCSIFALTMTU, (caddr_t)&ifr));
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

static struct ifaddr * 
ifaddr_byindex(int i)
{
    if (i > if_index || i == 0) {
	return (NULL);
    }
    return (ifnet_addrs[i - 1]);
}

/**
 ** vlan_parent synchronization routines
 **/
static __inline__ void
vlan_parent_retain(vlan_parent_ref vlp)
{
    OSIncrementAtomic(&vlp->vlp_retain_count);
}

static __inline__ void
vlan_parent_release(vlan_parent_ref vlp)
{
    UInt32		old_retain_count;

    old_retain_count = OSDecrementAtomic(&vlp->vlp_retain_count);
    switch (old_retain_count) {
    case 0:
	panic("vlan_parent_release: retain count is 0\n");
	break;
    case 1:
	if (g_vlan->verbose) {
	    struct ifnet * ifp = vlp->vlp_ifp;
	    printf("vlan_parent_release(%s%d)\n", ifp->if_name,
		   ifp->if_unit);
	}
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

	    printf("%s%d: %s msleep\n", ifp->if_name, ifp->if_unit, msg);
	}
	waited = 1;
	(void)msleep(vlp, vlan_lck_mtx, PZERO, msg, 0);
    }
    /* prevent other vlan parent remove/add from taking place */
    vlan_parent_flags_set_change_in_progress(vlp);
    if (g_vlan->verbose && waited) {
	struct ifnet * ifp = vlp->vlp_ifp;

	printf("%s: %s woke up\n", ifp->if_name, ifp->if_unit, msg);
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

	printf("%s%d: %s wakeup\n", ifp->if_name, ifp->if_unit, msg);
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
    vlan_parent_ref	vlp;

    vlan_lock();
    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	goto unlock_done;
    }
    vlp = ifv->ifv_vlp;
    if (vlp == NULL) {
	/* no parent, no need to program the multicast filter */
	goto unlock_done;
    }
    if (vlan_parent_flags_detaching(vlp)) {
	goto unlock_done;
    }
    vlan_parent_retain(vlp);
    vlan_parent_wait(vlp, "vlan_setmulti");

    /* check again, things could have changed */
    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	goto signal_done;
    }
    if (ifv->ifv_vlp != vlp) {
	/* vlan parent changed */
	goto signal_done;
    }
    if (vlp == NULL) {
	/* no parent, no need to program the multicast filter */
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
	req_mtu = ifv->ifv_ifp->if_mtu + ifv->ifv_mtufudge;
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
	       p->if_name, p->if_unit, error);
	FREE(vlp, M_VLAN);
	return (error);
    }
    LIST_INIT(&vlp->vlp_vlan_list);
    vlp->vlp_ifp = p;
    vlan_parent_retain(vlp);
    if (p->if_hwassist 
	& (IF_HWASSIST_VLAN_MTU | IF_HWASSIST_VLAN_TAGGING)) {
	vlan_parent_flags_set_supports_vlan_mtu(vlp);
    }
    *ret_vlp = vlp;
    return (0);
}

static void
vlan_parent_remove_all_vlans(vlan_parent_ref vlp)
{
    ifvlan_ref 		ifv;
    struct ifnet *	p;

    vlan_assert_lock_held();

    while ((ifv = LIST_FIRST(&vlp->vlp_vlan_list)) != NULL) {
	vlan_remove(ifv);
	vlan_unlock();
	vlan_if_detach(ifv->ifv_ifp);
	vlan_lock();
    }

    /* the vlan parent has no more VLAN's */
    p = vlp->vlp_ifp;
    ifnet_lock_exclusive(p);
    p->if_eflags &= ~IFEF_VLAN;
    ifnet_lock_done(p);
    LIST_REMOVE(vlp, vlp_parent_list);
    vlan_unlock();
    vlan_parent_release(vlp);
    vlan_lock();

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

static void
vlan_clone_attach(void)
{
    if_clone_attach(&vlan_cloner);
    vlan_lock_init();
    return;
}

static int
vlan_clone_create(struct if_clone *ifc, int unit)
{
    int 		error;
    ifvlan_ref		ifv;
    struct ifnet *	ifp;

    error = vlan_globals_init();
    if (error != 0) {
	return (error);
    }
    ifv = _MALLOC(sizeof(struct ifvlan), M_VLAN, M_WAITOK);
    bzero(ifv, sizeof(struct ifvlan));
    multicast_list_init(&ifv->ifv_multicast);

    /* use the interface name as the unique id for ifp recycle */
    if ((unsigned int)snprintf(ifv->ifv_name, sizeof(ifv->ifv_name), "%s%d",
			       ifc->ifc_name, unit) >= sizeof(ifv->ifv_name)) {
	FREE(ifv, M_VLAN);
	return (EINVAL);
    }
    error = dlil_if_acquire(APPLE_IF_FAM_VLAN,
			    ifv->ifv_name,
			    strlen(ifv->ifv_name),
			    &ifp);
    if (error) {
	FREE(ifv, M_VLAN);
	return (error);
    }
    ifp->if_name = ifc->ifc_name;
    ifp->if_unit = unit;
    ifp->if_family = APPLE_IF_FAM_VLAN;

#if 0
    /* NB: flags are not set here */
    ifp->if_linkmib = &ifv->ifv_mib;
    ifp->if_linkmiblen = sizeof ifv->ifv_mib;
    /* NB: mtu is not set here */
#endif 0

    ifp->if_ioctl = vlan_ioctl;
    ifp->if_set_bpf_tap = vlan_set_bpf_tap;
    ifp->if_free = vlan_if_free;
    ifp->if_output = vlan_output;
    ifp->if_hwassist = 0;
    ifp->if_addrlen = ETHER_ADDR_LEN; /* XXX ethernet specific */
    ifp->if_baudrate = 0;
    ifp->if_type = IFT_L2VLAN;
    ifp->if_hdrlen = ETHER_VLAN_ENCAP_LEN;
    
    /* XXX ethernet specific */
    ifp->if_broadcast.length = ETHER_ADDR_LEN;
    bcopy(etherbroadcastaddr, ifp->if_broadcast.u.buffer, ETHER_ADDR_LEN);
    
    error = dlil_if_attach(ifp);
    if (error) {
	dlil_if_release(ifp);
	FREE(ifv, M_VLAN);
	return (error);
    }
    ifp->if_private = ifv;
    ifv->ifv_ifp = ifp;

    /* attach as ethernet */
    bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
    return (0);
}

static void
vlan_remove(ifvlan_ref ifv)
{
    vlan_assert_lock_held();
    ifvlan_flags_set_detaching(ifv);
    vlan_unconfig(ifv->ifv_ifp);
    return;
}

static void
vlan_if_detach(struct ifnet * ifp)
{
    if (dlil_if_detach(ifp) != DLIL_WAIT_FOR_FREE) {
	vlan_if_free(ifp);
    }
    return;
}

static void
vlan_clone_destroy(struct ifnet *ifp)
{
    ifvlan_ref ifv;

    vlan_lock();
    ifv = ifp->if_private;
    if (ifv == NULL || ifp->if_type != IFT_L2VLAN) {
	vlan_unlock();
	return;
    }
    if (ifvlan_flags_detaching(ifv)) {
	vlan_unlock();
	return;
    }
    vlan_remove(ifv);
    vlan_unlock();
    vlan_if_detach(ifp);
    return;
}

static int 
vlan_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode, bpf_packet_func func)
{
    ifvlan_ref	ifv;

    vlan_lock();
    ifv = ifp->if_private;
    if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
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
    vlan_parent_ref		vlp;
	
    if (m == 0) {
	return (0);
    }
    if ((m->m_flags & M_PKTHDR) == 0) {
	m_freem_list(m);
	return (0);
    }
    vlan_lock();
    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv == NULL || ifvlan_flags_detaching(ifv)
	|| ifvlan_flags_ready(ifv) == 0) {
	vlan_unlock();
	m_freem_list(m);
	return (0);
    }
    vlp = ifv->ifv_vlp;
    if (vlp == NULL) {
	vlan_unlock();
	m_freem_list(m);
	return (0);
    }
    p = vlp->vlp_ifp;
    (void)ifnet_stat_increment_out(ifp, 1, m->m_pkthdr.len, 0);
    soft_vlan = (p->if_hwassist & IF_HWASSIST_VLAN_TAGGING) == 0;
    bpf_func = ifv->ifv_bpf_output;
    tag = ifv->ifv_tag;
    encaplen = ifv->ifv_encaplen;
    vlan_unlock();
    vlan_bpf_output(ifp, m, bpf_func);
	
    /* do not run parent's if_output() if the parent is not up */
    if ((p->if_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
	m_freem(m);
	ifp->if_collisions++;
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
	    printf("%s%d: unable to prepend VLAN header\n", ifp->if_name,
		   ifp->if_unit);
	    ifp->if_oerrors++;
	    return (0);
	}
	/* M_PREPEND takes care of m_len, m_pkthdr.len for us */
	if (m->m_len < (int)sizeof(*evl)) {
	    m = m_pullup(m, sizeof(*evl));
	    if (m == NULL) {
		printf("%s%d: unable to pullup VLAN header\n", ifp->if_name,
		       ifp->if_unit);
		ifp->if_oerrors++;
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
    return dlil_output(p, 0, m, NULL, NULL, 1);
}

static int
vlan_input(struct mbuf * m, char * frame_header, struct ifnet * p,
	   __unused u_long protocol_family, __unused int sync_ok)
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
	switch (p->if_type) {
	case IFT_ETHER:
	    if (m->m_len < ETHER_VLAN_ENCAP_LEN) {
		m_freem(m);
		return 0;
	    }
	    evl = (struct ether_vlan_header *)frame_header;
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
		   p->if_type);
	    m_freem(m);
	    return 0;
	    break;
	}
    }
    if (tag != 0) {
	ifvlan_ref		ifv;

	if ((p->if_eflags & IFEF_VLAN) == 0) {
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
	    || (ifp->if_flags & IFF_UP) == 0) {
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
	(void)ifnet_stat_increment_in(ifp, 1, 
				      m->m_pkthdr.len + ETHER_HDR_LEN, 0);
	vlan_bpf_input(ifp, m, bpf_func, frame_header, ETHER_HDR_LEN, 
		       soft_vlan ? ETHER_VLAN_ENCAP_LEN : 0);
	/* We found a vlan interface, inject on that interface. */
	dlil_input_packet(ifp, m, frame_header);
    } else {
	/* Send priority-tagged packet up through the parent */
	dlil_input_packet(p, m, frame_header);
    }
    return 0;
}

#define VLAN_CONFIG_PROGRESS_VLP_RETAINED	0x1
#define VLAN_CONFIG_PROGRESS_IN_LIST		0x2

static int
vlan_config(struct ifnet * ifp, struct ifnet * p, int tag)
{
    int			error;
    int			first_vlan = 0;
    ifvlan_ref 		ifv = NULL;
    struct ifaddr *	ifa1;
    struct ifaddr *	ifa2;
    vlan_parent_ref	new_vlp = NULL;
    int			need_vlp_release = 0;
    u_int32_t		progress = 0;
    struct sockaddr_dl *sdl1;
    struct sockaddr_dl *sdl2;
    vlan_parent_ref	vlp = NULL;

    /* pre-allocate space for vlan_parent, in case we're first */
    error = vlan_parent_create(p, &new_vlp);
    if (error != 0) {
	return (error);
    }

    vlan_lock();
    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv != NULL && ifv->ifv_vlp != NULL) {
	vlan_unlock();
	vlan_parent_release(new_vlp);
	return (EBUSY);
    }
    vlp = parent_list_lookup(p);
    if (vlp != NULL) {
	if (vlan_parent_lookup_tag(vlp, tag) != NULL) {
	    /* already a VLAN with that tag on this interface */
	    error = EADDRINUSE;
	    goto unlock_done;
	}
    }
    else {
	/* we're the first VLAN on this interface */
	LIST_INSERT_HEAD(&g_vlan->parent_list, new_vlp, vlp_parent_list);
	vlp = new_vlp;
    }

    /* need to wait to ensure no one else is trying to add/remove */
    vlan_parent_retain(vlp);
    progress |= VLAN_CONFIG_PROGRESS_VLP_RETAINED;
    vlan_parent_wait(vlp, "vlan_config");

    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv == NULL) {
	error = EOPNOTSUPP;
	goto signal_done;
    }
    if (vlan_parent_flags_detaching(vlp)
	|| ifvlan_flags_detaching(ifv) || ifv->ifv_vlp != NULL) {
	error = EBUSY;
	goto signal_done;
    }

    /* check again because someone might have gotten in */
    if (vlan_parent_lookup_tag(vlp, tag) != NULL) {
	/* already a VLAN with that tag on this interface */
	error = EADDRINUSE;
	goto signal_done;
    }

    if (vlan_parent_no_vlans(vlp)) {
	first_vlan = 1;
    }
    vlan_parent_add_vlan(vlp, ifv, tag);
    progress |= VLAN_CONFIG_PROGRESS_IN_LIST;

    /* check whether bond interface is using parent interface */
    ifnet_lock_exclusive(p);
    if ((p->if_eflags & IFEF_BOND) != 0) {
	ifnet_lock_done(p);
	/* don't allow VLAN over interface that's already part of a bond */
	error = EBUSY;
	goto signal_done;
    }
    /* prevent BOND interface from using it */
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
	/* mark the parent interface up */
	ifnet_lock_exclusive(p);
	p->if_flags |= IFF_UP;
	ifnet_lock_done(p);
	(void)dlil_ioctl(0, p, SIOCSIFFLAGS, (caddr_t)NULL);
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
    ifp->if_mtu = ETHERMTU - ifv->ifv_mtufudge;

    /*
     * Copy only a selected subset of flags from the parent.
     * Other flags are none of our business.
     */
    ifp->if_flags |= (p->if_flags &
		      (IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX));
    /*
     * If the parent interface can do hardware-assisted
     * VLAN encapsulation, then propagate its hardware-
     * assisted checksumming flags.
     */
    if (p->if_hwassist & IF_HWASSIST_VLAN_TAGGING) {
	ifp->if_hwassist |= IF_HWASSIST_CSUM_FLAGS(p->if_hwassist);
    }

    /* set our ethernet address to that of the parent */
    ifa1 = ifaddr_byindex(ifp->if_index);
    ifa2 = ifaddr_byindex(p->if_index);
    sdl1 = (struct sockaddr_dl *)ifa1->ifa_addr;
    sdl2 = (struct sockaddr_dl *)ifa2->ifa_addr;
    sdl1->sdl_type = IFT_ETHER;
    sdl1->sdl_alen = ETHER_ADDR_LEN;
    bcopy(LLADDR(sdl2), LLADDR(sdl1), ETHER_ADDR_LEN);

    ifp->if_flags |= IFF_RUNNING;
    ifvlan_flags_set_ready(ifv);
    vlan_parent_signal(vlp, "vlan_config");
    vlan_unlock();
    if (new_vlp != vlp) {
	/* throw it away, it wasn't needed */
	vlan_parent_release(new_vlp);
    }
    return 0;

 signal_done:
    vlan_assert_lock_held();
    vlan_parent_signal(vlp, "vlan_config");

 unlock_done:
    if ((progress & VLAN_CONFIG_PROGRESS_IN_LIST) != 0) {
	vlan_parent_remove_vlan(vlp, ifv);
    }
    if (!vlan_parent_flags_detaching(vlp) && vlan_parent_no_vlans(vlp)) {
	/* the vlan parent has no more VLAN's */
	ifnet_lock_exclusive(p);
	p->if_eflags &= ~IFEF_VLAN;
	ifnet_lock_done(p);
	LIST_REMOVE(vlp, vlp_parent_list);
	/* release outside of the lock below */
	need_vlp_release = 1;
    }
    vlan_unlock();

    if ((progress & VLAN_CONFIG_PROGRESS_VLP_RETAINED) != 0) {
	vlan_parent_release(vlp);
    }
    if (need_vlp_release) {
	vlan_parent_release(vlp);
    }
    if (new_vlp != vlp) {
	vlan_parent_release(new_vlp);
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
	     "%s%d", p->if_name, p->if_unit);
    if ((*p->if_ioctl)(p, SIOCGIFMEDIA, (caddr_t)&ifmr) == 0
	&& ifmr.ifm_count > 0 && ifmr.ifm_status & IFM_AVALID) {
	u_long	event;
	
	event = (ifmr.ifm_status & IFM_ACTIVE)
	    ? KEV_DL_LINK_ON : KEV_DL_LINK_OFF;
	interface_link_event(ifp, event);
    }
    return;
}

static int
vlan_unconfig(struct ifnet * ifp)
{
    int			error = 0;
    struct ifaddr *	ifa;
    ifvlan_ref		ifv;
    int			last_vlan = 0;
    int			need_vlp_release = 0;
    struct ifnet *	p;
    struct sockaddr_dl *sdl;
    vlan_parent_ref	vlp;

    vlan_assert_lock_held();
    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv == NULL) {
	return (0);
    }
    vlp = ifv->ifv_vlp;
    if (vlp == NULL) {
	return (0);
    }
    vlan_parent_retain(vlp);
    vlan_parent_wait(vlp, "vlan_unconfig");

    /* check again because another thread could be in vlan_unconfig */
    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv == NULL) {
	goto signal_done;
    }
    if (ifv->ifv_vlp != vlp) {
	/* vlan parent changed */
	goto signal_done;
    }
    need_vlp_release++;
    p = vlp->vlp_ifp;

    /* remember whether we're the last VLAN on the parent */
    if (LIST_NEXT(LIST_FIRST(&vlp->vlp_vlan_list), ifv_vlan_list) == NULL) {
	if (g_vlan->verbose) {
	    printf("vlan_unconfig: last vlan on %s%d\n",
		   p->if_name, p->if_unit);
	}
	last_vlan = 1;
    }

    /* back-out any effect our mtu might have had on the parent */
    (void)vlan_new_mtu(ifp, ETHERMTU - ifv->ifv_mtufudge);

    vlan_unlock();

    /* detach VLAN "protocol" */
    if (last_vlan) {
	(void)vlan_detach_protocol(p);
    }

    /* un-join multicast on parent interface */
    (void)multicast_list_remove(&ifv->ifv_multicast);

    vlan_lock();

    /* Disconnect from parent. */
    vlan_parent_remove_vlan(vlp, ifv);

    /* return to the state we were in before SIFVLAN */
    ifp->if_mtu = 0;
    ifp->if_flags &= ~(IFF_BROADCAST | IFF_MULTICAST 
		       | IFF_SIMPLEX | IFF_RUNNING);
    ifp->if_hwassist = 0;
    ifv->ifv_flags = 0;
    ifv->ifv_mtufudge = 0;

    /* Clear our MAC address. */
    ifa = ifaddr_byindex(ifp->if_index);
    sdl = (struct sockaddr_dl *)(ifa->ifa_addr);
    sdl->sdl_type = IFT_L2VLAN;
    sdl->sdl_alen = 0;
    bzero(LLADDR(sdl), ETHER_ADDR_LEN);

    if (!vlan_parent_flags_detaching(vlp) && vlan_parent_no_vlans(vlp)) {
	/* the vlan parent has no more VLAN's */
	ifnet_lock_exclusive(p);
	p->if_eflags &= ~IFEF_VLAN;
	ifnet_lock_done(p);
	LIST_REMOVE(vlp, vlp_parent_list);
	/* release outside of the lock below */
	need_vlp_release++;
    }

 signal_done:
    vlan_parent_signal(vlp, "vlan_unconfig");
    vlan_unlock();
    vlan_parent_release(vlp);	/* one because we waited */

    while (need_vlp_release--) {
	vlan_parent_release(vlp);
    }
    vlan_lock();
    return (error);
}

static int
vlan_set_promisc(struct ifnet * ifp)
{
    int 			error = 0;
    ifvlan_ref			ifv;
    vlan_parent_ref		vlp;

    vlan_lock();
    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	error = (ifv == NULL) ? EOPNOTSUPP : EBUSY;
	goto done;
    }

    vlp = ifv->ifv_vlp;
    if (vlp == NULL) {
	goto done;
    }
    if ((ifp->if_flags & IFF_PROMISC) != 0) {
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
    return (error);
}

static int
vlan_new_mtu(struct ifnet * ifp, int mtu)
{
    struct ifdevmtu *	devmtu_p;
    int			error = 0;
    ifvlan_ref		ifv;
    int			max_mtu;
    int			new_mtu = 0;
    int			req_mtu;
    vlan_parent_ref	vlp;

    vlan_assert_lock_held();
    ifv = (ifvlan_ref)ifp->if_private;
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
	ifp->if_mtu = mtu;
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
    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	vlan_unlock();
	return ((ifv == NULL) ? EOPNOTSUPP : EBUSY);
    }
    vlp = ifv->ifv_vlp;
    if (vlp == NULL || vlan_parent_flags_detaching(vlp)) {
	vlan_unlock();
	if (mtu != 0) {
	    return (EINVAL);
	}
	return (0);
    }
    vlan_parent_retain(vlp);
    vlan_parent_wait(vlp, "vlan_set_mtu");

    /* check again, something might have changed */
    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	error = (ifv == NULL) ? EOPNOTSUPP : EBUSY;
	goto signal_done;
    }
    if (ifv->ifv_vlp != vlp) {
	/* vlan parent changed */
	goto signal_done;
    }
    if (vlp == NULL || vlan_parent_flags_detaching(vlp)) {
	if (mtu != 0) {
	    error = EINVAL;
	}
	goto signal_done;
    }
    error = vlan_new_mtu(ifp, mtu);

 signal_done:
    vlan_parent_signal(vlp, "vlan_set_mtu");
    vlan_unlock();
    vlan_parent_release(vlp);

    return (error);
}

static int
vlan_ioctl(ifnet_t ifp, u_int32_t cmd, void * data)
{
    struct ifdevmtu *	devmtu_p;
    int 		error = 0;
    struct ifaddr *	ifa;
    struct ifmediareq64 * ifmr;
    struct ifreq *	ifr;
    ifvlan_ref		ifv;
    struct ifnet *	p;
    u_short		tag;
    user_addr_t		user_addr;
    vlan_parent_ref	vlp;
    struct vlanreq 	vlr;

    if (ifp->if_type != IFT_L2VLAN) {
	return (EOPNOTSUPP);
    }
    ifr = (struct ifreq *)data;
    ifa = (struct ifaddr *)data;

    switch (cmd) {
    case SIOCSIFADDR:
    ifnet_set_flags(ifp, IFF_UP, IFF_UP);
	break;

    case SIOCGIFMEDIA64:
    case SIOCGIFMEDIA:
	vlan_lock();
	ifv = (ifvlan_ref)ifp->if_private;
	if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	    vlan_unlock();
	    return (ifv == NULL ? EOPNOTSUPP : EBUSY);
	}
	p = (ifv->ifv_vlp == NULL) ? NULL : ifv->ifv_vlp->vlp_ifp;
	vlan_unlock();
	ifmr = (struct ifmediareq64 *)data;
	user_addr = (cmd == SIOCGIFMEDIA64)
	    ? ifmr->ifm_ifmu.ifmu_ulist64
	    : CAST_USER_ADDR_T(ifmr->ifm_ifmu.ifmu_ulist32);
	if (p != NULL) {
	    struct ifmediareq64		p_ifmr;

	    bzero(&p_ifmr, sizeof(p_ifmr));
	    error = dlil_ioctl(0, p, SIOCGIFMEDIA, (caddr_t)&p_ifmr);
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
	ifv = (ifvlan_ref)ifp->if_private;
	if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	    vlan_unlock();
	    return (ifv == NULL ? EOPNOTSUPP : EBUSY);
	}
	vlp = ifv->ifv_vlp;
	if (vlp != NULL) {
	    int		min_mtu = vlp->vlp_devmtu.ifdm_min - ifv->ifv_mtufudge;
	    devmtu_p = &ifr->ifr_devmtu;
	    devmtu_p->ifdm_current = ifp->if_mtu;
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
	    if (p->if_type != IFT_ETHER	&& p->if_type != IFT_IEEE8023ADLAG) {
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
	} else {
	    vlan_lock();
	    ifv = (ifvlan_ref)ifp->if_private;
	    if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
		vlan_unlock();
		error = (ifv == NULL ? EOPNOTSUPP : EBUSY);
		break;
	    }
	    error = vlan_unconfig(ifp);
	    vlan_unlock();
	    if (error == 0) {
		interface_link_event(ifp, KEV_DL_LINK_OFF);
	    }
	}
	break;
		
    case SIOCGIFVLAN:
	bzero(&vlr, sizeof vlr);
	vlan_lock();
	ifv = (ifvlan_ref)ifp->if_private;
	if (ifv == NULL || ifvlan_flags_detaching(ifv)) {
	    vlan_unlock();
	    return (ifv == NULL ? EOPNOTSUPP : EBUSY);
	}
	p = (ifv->ifv_vlp == NULL) ? NULL : ifv->ifv_vlp->vlp_ifp;
	tag = ifv->ifv_tag;
	vlan_unlock();
	if (p != NULL) {
	    snprintf(vlr.vlr_parent, sizeof(vlr.vlr_parent),
		     "%s%d", p->if_name, p->if_unit);
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
    vlan_lock();
    ifv = (ifvlan_ref)ifp->if_private;
    if (ifv == NULL) {
	vlan_unlock();
	return;
    }
    ifp->if_private = NULL;
    vlan_unlock();
    dlil_if_release(ifp);
    FREE(ifv, M_VLAN);
}

static void
vlan_event(struct ifnet	* p, struct kev_msg * event)
{
    vlan_parent_ref	vlp;

    /* Check if the interface we are attached to is being detached */
    if (event->vendor_code != KEV_VENDOR_APPLE
	|| event->kev_class != KEV_NETWORK_CLASS
	|| event->kev_subclass != KEV_DL_SUBCLASS) {
	return;
    }
    switch (event->event_code) {
    case KEV_DL_IF_DETACHING:
    case KEV_DL_LINK_OFF:
    case KEV_DL_LINK_ON:
	break;
    default:
	return;
    }
    vlan_lock();
    if ((p->if_eflags & IFEF_VLAN) == 0) {
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
    switch (event->event_code) {
    case KEV_DL_IF_DETACHING:
	vlan_parent_flags_set_detaching(vlp);
	vlan_parent_remove_all_vlans(vlp);
	break;
		
    case KEV_DL_LINK_OFF:
    case KEV_DL_LINK_ON:
	vlan_parent_link_event(vlp, event->event_code);
	break;
    default:
	break;
    }
    vlan_unlock();
    return;
}

static void
interface_link_event(struct ifnet * ifp, u_long event_code)
{
    struct {
	struct kern_event_msg	header;
	u_long			unit;
	char			if_name[IFNAMSIZ];
    } event;

    event.header.total_size    = sizeof(event);
    event.header.vendor_code   = KEV_VENDOR_APPLE;
    event.header.kev_class     = KEV_NETWORK_CLASS;
    event.header.kev_subclass  = KEV_DL_SUBCLASS;
    event.header.event_code    = event_code;
    event.header.event_data[0] = ifp->if_family;
    event.unit                 = (u_long) ifp->if_unit;
    strncpy(event.if_name, ifp->if_name, IFNAMSIZ);
    dlil_event(ifp, &event.header);
    return;
}

static void
vlan_parent_link_event(vlan_parent_ref vlp, u_long event_code)
{
    ifvlan_ref ifv;

    LIST_FOREACH(ifv, &vlp->vlp_vlan_list, ifv_vlan_list) {
	interface_link_event(ifv->ifv_ifp, event_code);
    }
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
    int  			error;
    struct dlil_proto_reg_str   reg;
	
    bzero(&reg, sizeof(reg));
    TAILQ_INIT(&reg.demux_desc_head);
    reg.interface_family = ifp->if_family;
    reg.unit_number      = ifp->if_unit;
    reg.input            = vlan_input;
    reg.event            = vlan_event;
    reg.protocol_family  = PF_VLAN;
    error = dlil_attach_protocol(&reg);
    if (error) {
	printf("vlan_proto_attach(%s%d) dlil_attach_protocol failed, %d\n",
	       ifp->if_name, ifp->if_unit, error);
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

    error = dlil_detach_protocol(ifp, PF_VLAN);
    if (error) {
	printf("vlan_proto_detach(%s%d) dlil_detach_protocol failed, %d\n",
	       ifp->if_name, ifp->if_unit, error);
    }
	
    return (error);
}

/*
 * DLIL interface family functions
 *   We use the ethernet dlil functions, since that's all we support.
 *   If we wanted to handle multiple LAN types (tokenring, etc.), we'd
 *   call the appropriate routines for that LAN type instead of hard-coding
 *   ethernet.
 */
extern int ether_add_if(struct ifnet *ifp);
extern int ether_del_if(struct ifnet *ifp);
extern int ether_init_if(struct ifnet *ifp);
extern int ether_add_proto_old(struct ifnet *ifp, u_long protocol_family,
				struct ddesc_head_str *desc_head);

extern int ether_attach_inet(struct ifnet *ifp, u_long protocol_family);
extern int ether_detach_inet(struct ifnet *ifp, u_long protocol_family);
extern int ether_attach_inet6(struct ifnet *ifp, u_long protocol_family);
extern int ether_detach_inet6(struct ifnet *ifp, u_long protocol_family);

static int
vlan_attach_inet(struct ifnet *ifp, u_long protocol_family)
{
    return (ether_attach_inet(ifp, protocol_family));
}

static int
vlan_detach_inet(struct ifnet *ifp, u_long protocol_family)
{
    return (ether_detach_inet(ifp, protocol_family));
}

static int
vlan_attach_inet6(struct ifnet *ifp, u_long protocol_family)
{
    return (ether_attach_inet6(ifp, protocol_family));
}

static int
vlan_detach_inet6(struct ifnet *ifp, u_long protocol_family)
{
    return (ether_detach_inet6(ifp, protocol_family));
}

static int
vlan_add_if(struct ifnet *ifp)
{
    return (ether_add_if(ifp));
}

static int
vlan_del_if(struct ifnet *ifp)
{
    return (ether_del_if(ifp));
}


__private_extern__ int
vlan_family_init(void)
{
    int error=0;
    struct dlil_ifmod_reg_str  ifmod_reg;
    
    bzero(&ifmod_reg, sizeof(ifmod_reg));
    ifmod_reg.add_if = vlan_add_if;
    ifmod_reg.del_if = vlan_del_if;
    ifmod_reg.init_if = NULL;
    ifmod_reg.add_proto = ether_add_proto_old;
    ifmod_reg.del_proto = ether_del_proto;
    ifmod_reg.ifmod_ioctl = ether_ioctl;
    ifmod_reg.shutdown = NULL;

    if (dlil_reg_if_modules(APPLE_IF_FAM_VLAN, &ifmod_reg)) {
	printf("WARNING: vlan_family_init -- "
	       "Can't register if family modules\n");
	error = EIO;
	goto done;
    }

    error = dlil_reg_proto_module(PF_INET, APPLE_IF_FAM_VLAN, 
				  vlan_attach_inet, vlan_detach_inet);
    if (error != 0) {
	printf("dlil_reg_proto_module failed for AF_INET error=%d\n",
	       error);
	goto done;
    }
    error = dlil_reg_proto_module(PF_INET6, APPLE_IF_FAM_VLAN, 
				  vlan_attach_inet6, vlan_detach_inet6);
    if (error != 0) {
	printf("dlil_reg_proto_module failed for AF_INET6 error=%d\n",
	       error);
	goto done;
    }
    vlan_clone_attach();

 done:
    return (error);
}
