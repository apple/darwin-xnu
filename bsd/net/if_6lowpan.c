/*
 * Copyright (c) 2017-2019 Apple Inc. All rights reserved.
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
 */
/*
 * if_6lowpan.c - pseudo-device driver for IEEE 802.15.4 .
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
#include <net/if_6lowpan_var.h>
#include <net/frame802154.h>
#include <net/sixxlowpan.h>
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

#define SIXLOWPANNAME   "6lowpan"

struct ifnet *p_6lowpan_ifnet = NULL;

extern errno_t nd6_lookup_ipv6(ifnet_t interface,
    const struct sockaddr_in6 *ip6_dest, struct sockaddr_dl *ll_dest,
    size_t ll_dest_len, route_t hint, mbuf_t packet);


typedef int (bpf_callback_func)(struct ifnet *, struct mbuf *);
typedef int (if_set_bpf_tap_func)(struct ifnet *ifp, int mode, bpf_callback_func * func);

static __inline__ lck_grp_t *
my_lck_grp_alloc_init(const char * grp_name)
{
	lck_grp_t *             grp;
	lck_grp_attr_t *        grp_attrs;

	grp_attrs = lck_grp_attr_alloc_init();
	grp = lck_grp_alloc_init(grp_name, grp_attrs);
	lck_grp_attr_free(grp_attrs);
	return grp;
}

static __inline__ lck_mtx_t *
my_lck_mtx_alloc_init(lck_grp_t * lck_grp)
{
	lck_attr_t *    lck_attrs;
	lck_mtx_t *             lck_mtx;

	lck_attrs = lck_attr_alloc_init();
	lck_mtx = lck_mtx_alloc_init(lck_grp, lck_attrs);
	lck_attr_free(lck_attrs);
	return lck_mtx;
}

static lck_mtx_t *sixlowpan_lck_mtx;

static __inline__ void
sixlowpan_lock_init(void)
{
	lck_grp_t *lck_grp;

	lck_grp = my_lck_grp_alloc_init("if_6lowpan");
	sixlowpan_lck_mtx = my_lck_mtx_alloc_init(lck_grp);
}

static __inline__ void
sixlowpan_assert_lock_held(void)
{
	lck_mtx_assert(sixlowpan_lck_mtx, LCK_MTX_ASSERT_OWNED);
	return;
}

#ifdef __UNUSED__
static __inline__ void
sixlowpan_assert_lock_not_held(void)
{
	lck_mtx_assert(sixlowpan_lck_mtx, LCK_MTX_ASSERT_NOTOWNED);
	return;
}
#endif

static __inline__ void
sixlowpan_lock(void)
{
	lck_mtx_lock(sixlowpan_lck_mtx);
	return;
}

static __inline__ void
sixlowpan_unlock(void)
{
	lck_mtx_unlock(sixlowpan_lck_mtx);
	return;
}

struct if6lpan;
LIST_HEAD(if6lpan_list, if6lpan);

typedef LIST_ENTRY(if6lpan)
if6lpan_entry;

#define IF6LPAN_SIGNATURE       0x6666face
struct if6lpan {
	if6lpan_entry           if6lpan_list;
	char                    if6lpan_name[IFNAMSIZ]; /* our unique id */
	char                    if6lpan_addr[IEEE802154_ADDR_LEN]; /* our LL address */
	struct ifnet *          if6lpan_ifp;    /* our interface */
	struct ifnet *          if6lpan_pifp;   /* parent interface */
#define IF6LPANF_DETACHING      0x1             /* interface is detaching */
#define IF6LPANF_READY          0x2             /* interface is ready */
	u_int32_t               if6lpan_flags;
	bpf_packet_func         if6lpan_bpf_input;
	bpf_packet_func         if6lpan_bpf_output;
	int32_t                 if6lpan_retain_count;
	u_int32_t               if6lpan_signature;      /* IF6LPAN_SIGNATURE */
	u_int8_t                if6lpan_ieee802154_seq;
};

typedef struct if6lpan * if6lpan_ref;

static __inline__ int
if6lpan_flags_ready(if6lpan_ref ifl)
{
	return (ifl->if6lpan_flags & IF6LPANF_READY) != 0;
}

static __inline__ void
if6lpan_flags_set_ready(if6lpan_ref ifl)
{
	ifl->if6lpan_flags |= IF6LPANF_READY;
	return;
}

static __inline__ void
if6lpan_set_addr(if6lpan_ref ifl, caddr_t ether_addr)
{
	ifl->if6lpan_addr[0] = 0x66;
	ifl->if6lpan_addr[1] = 0x66;
	bcopy(ether_addr, &ifl->if6lpan_addr[2], ETHER_ADDR_LEN);
	return;
}

#ifdef __UNUSED__
static __inline__ u_int8_t*
if6lpan_get_addr(if6lpan_ref ifl)
{
	return ifl->ifl6lpan_addr;
}
#endif

static __inline__ int
if6lpan_flags_detaching(if6lpan_ref ifl)
{
	return (ifl->if6lpan_flags & IF6LPANF_DETACHING) != 0;
}

static __inline__ void
if6lpan_flags_set_detaching(if6lpan_ref ifl)
{
	ifl->if6lpan_flags |= IF6LPANF_DETACHING;
	return;
}

static  int sixlowpan_clone_create(struct if_clone *, u_int32_t, void *);
static  int sixlowpan_clone_destroy(struct ifnet *);
static  int sixlowpan_input(ifnet_t ifp, protocol_family_t protocol,
    mbuf_t m, char *frame_header);
static  int sixlowpan_output(struct ifnet *ifp, struct mbuf *m);
static  int sixlowpan_ioctl(ifnet_t ifp, u_long cmd, void *addr);
static  int sixlowpan_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode,
    bpf_packet_func func);
static  int sixlowpan_attach_protocol(struct ifnet *ifp);
static  int sixlowpan_detach_protocol(struct ifnet *ifp);
static  int sixlowpan_unconfig(if6lpan_ref ifl);
static  int sixlowpan_config(struct ifnet *ifp, struct ifnet *p);
static  void sixlowpan_if_free(struct ifnet *ifp);
static  int sixlowpan_remove(if6lpan_ref ifl);
static  int sixlowpan_framer_extended(struct ifnet *ifp, struct mbuf **m,
    const struct sockaddr *ndest, const char *edst,
    const char *ether_type, u_int32_t *prepend_len, u_int32_t *postpend_len);

#define SIXLOWPAN_MAXUNIT       IF_MAXUNIT
#define SIXLOWPAN_ZONE_MAX_ELEM MIN(IFNETS_MAX, SIXLOWPAN_MAXUNIT)

static struct if_clone sixlowpan_cloner = IF_CLONE_INITIALIZER(SIXLOWPANNAME,
    sixlowpan_clone_create,
    sixlowpan_clone_destroy,
    0,
    SIXLOWPAN_MAXUNIT,
    SIXLOWPAN_ZONE_MAX_ELEM,
    sizeof(struct if6lpan));

/**
** if6lpan_ref routines
**/
static void
if6lpan_retain(if6lpan_ref ifl)
{
	if (ifl->if6lpan_signature != IF6LPAN_SIGNATURE) {
		panic("if6lpan_retain: bad signature\n");
	}
	if (ifl->if6lpan_retain_count == 0) {
		panic("if6lpan_retain: retain count is 0\n");
	}
	OSIncrementAtomic(&ifl->if6lpan_retain_count);
}

static void
if6lpan_release(if6lpan_ref ifl)
{
	u_int32_t old_retain_count;

	if (ifl->if6lpan_signature != IF6LPAN_SIGNATURE) {
		panic("if6lpan_release: bad signature\n");
	}
	old_retain_count = OSDecrementAtomic(&ifl->if6lpan_retain_count);
	switch (old_retain_count) {
	case 0:
		panic("if6lpan_release: retain count is 0\n");
		break;
	case 1:
		ifl->if6lpan_signature = 0;
		if_clone_softc_deallocate(&sixlowpan_cloner, ifl);
		break;
	default:
		break;
	}
	return;
}

static if6lpan_ref
ifnet_get_if6lpan(struct ifnet * ifp)
{
	if6lpan_ref             ifl;

	ifl = (if6lpan_ref)ifnet_softc(ifp);
	return ifl;
}

static if6lpan_ref
ifnet_get_if6lpan_retained(struct ifnet * ifp)
{
	if6lpan_ref             ifl;

	ifl = ifnet_get_if6lpan(ifp);
	if (ifl == NULL) {
		return NULL;
	}
	if (if6lpan_flags_detaching(ifl)) {
		return NULL;
	}
	if6lpan_retain(ifl);
	return ifl;
}

static int
sixlowpan_clone_attach(void)
{
	int error;

	error = if_clone_attach(&sixlowpan_cloner);
	if (error != 0) {
		return error;
	}
	sixlowpan_lock_init();
	return 0;
}

static int
sixlowpan_demux(
	__unused ifnet_t ifp,
	__unused mbuf_t m,
	__unused char *frame_header,
	protocol_family_t *protocol_family)
{
	*protocol_family = PF_INET6;
	return 0;
}

static errno_t
sixlowpan_add_proto(__unused ifnet_t interface, protocol_family_t protocol,
    __unused const struct ifnet_demux_desc *demux_array,
    __unused u_int32_t demux_count)
{
	if (protocol == PF_INET6) {
		return 0;
	}
	return ENOPROTOOPT;
}

static errno_t
sixlowpan_del_proto(__unused ifnet_t interface, __unused protocol_family_t protocol)
{
	return 0;
}

static int
sixlowpan_clone_create(struct if_clone *ifc, u_int32_t unit, __unused void *params)
{
	int                             error;
	if6lpan_ref                     ifl;
	ifnet_t                         ifp;
	struct ifnet_init_eparams       if_epraram;

	ifl = if_clone_softc_allocate(&sixlowpan_cloner);
	if (ifl == NULL) {
		return ENOBUFS;
	}
	ifl->if6lpan_retain_count = 1;
	ifl->if6lpan_signature = IF6LPAN_SIGNATURE;

	/* use the interface name as the unique id for ifp recycle */
	if ((unsigned int)
	    snprintf(ifl->if6lpan_name, sizeof(ifl->if6lpan_name), "%s%d",
	    ifc->ifc_name, unit) >= sizeof(ifl->if6lpan_name)) {
		if6lpan_release(ifl);
		return EINVAL;
	}

	bzero(&if_epraram, sizeof(if_epraram));
	if_epraram.ver = IFNET_INIT_CURRENT_VERSION;
	if_epraram.len = sizeof(if_epraram);
	if_epraram.flags = IFNET_INIT_LEGACY;
	if_epraram.uniqueid = ifl->if6lpan_name;
	if_epraram.uniqueid_len = strlen(ifl->if6lpan_name);
	if_epraram.name = ifc->ifc_name;
	if_epraram.unit = unit;
	if_epraram.family = IFNET_FAMILY_6LOWPAN;
	if_epraram.type = IFT_6LOWPAN;
	if_epraram.output = sixlowpan_output;
	if_epraram.demux = sixlowpan_demux;
	if_epraram.add_proto = sixlowpan_add_proto;
	if_epraram.del_proto = sixlowpan_del_proto;
	if_epraram.framer_extended = sixlowpan_framer_extended;
	if_epraram.softc = ifl;
	if_epraram.ioctl = sixlowpan_ioctl;
	if_epraram.set_bpf_tap = sixlowpan_set_bpf_tap;
	if_epraram.detach = sixlowpan_if_free;
	error = ifnet_allocate_extended(&if_epraram, &ifp);

	if (error) {
		if6lpan_release(ifl);
		return error;
	}

	ifnet_set_offload(ifp, 0);
	ifnet_set_addrlen(ifp, IEEE802154_ADDR_LEN);
	ifnet_set_baudrate(ifp, 0);
	// TODO: ifnet_set_hdrlen(ifp, IEEE802154_ENCAP_LEN);

	error = ifnet_attach(ifp, NULL);
	if (error) {
		ifnet_release(ifp);
		if6lpan_release(ifl);
		return error;
	}
	ifl->if6lpan_ifp = ifp;

	p_6lowpan_ifnet = ifp;
	/* TODO:  attach as IEEE 802.15.4 with no FCS */
	bpfattach(ifp, DLT_IEEE802_15_4_NOFCS, IEEE802154_ENCAP_LEN);
	return 0;
}

static int
sixlowpan_remove(if6lpan_ref ifl)
{
	sixlowpan_assert_lock_held();
	if (if6lpan_flags_detaching(ifl)) {
		return 0;
	}
	if6lpan_flags_set_detaching(ifl);
	sixlowpan_unconfig(ifl);
	return 1;
}


static int
sixlowpan_clone_destroy(struct ifnet *ifp)
{
	if6lpan_ref ifl;

	sixlowpan_lock();
	ifl = ifnet_get_if6lpan_retained(ifp);
	if (ifl == NULL) {
		sixlowpan_unlock();
		return 0;
	}
	if (sixlowpan_remove(ifl) == 0) {
		sixlowpan_unlock();
		if6lpan_release(ifl);
		return 0;
	}
	sixlowpan_unlock();
	if6lpan_release(ifl);
	ifnet_detach(ifp);
	p_6lowpan_ifnet = NULL;
	return 0;
}

static int
sixlowpan_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode, bpf_packet_func func)
{
	if6lpan_ref     ifl;

	sixlowpan_lock();
	ifl = ifnet_get_if6lpan_retained(ifp);
	if (ifl == NULL) {
		sixlowpan_unlock();
		return ENODEV;
	}
	switch (mode) {
	case BPF_TAP_DISABLE:
		ifl->if6lpan_bpf_input = ifl->if6lpan_bpf_output = NULL;
		break;

	case BPF_TAP_INPUT:
		ifl->if6lpan_bpf_input = func;
		break;

	case BPF_TAP_OUTPUT:
		ifl->if6lpan_bpf_output = func;
		break;

	case BPF_TAP_INPUT_OUTPUT:
		ifl->if6lpan_bpf_input = ifl->if6lpan_bpf_output = func;
		break;
	default:
		break;
	}
	sixlowpan_unlock();
	if6lpan_release(ifl);
	return 0;
}

/*
 * 6lowpan output routine.
 * Header compression on the protocol payload
 * Frame the compressed payload in 802.15.4 Data Frame
 * Encapsulate the 802.15.4 frame in an Ethernet frame.
 */
static int
sixlowpan_output(struct ifnet * ifp, struct mbuf * m)
{
	struct ifnet            *p_intf = NULL;
	if6lpan_ref             ifl = NULL;
	struct flowadv          adv = { .code = FADV_SUCCESS };
	int                     err = 0;
	char                    link_layer_dest[ETHER_ADDR_LEN];
	bpf_packet_func         bpf_func;

	u_int16_t ethertype = htons(ETHERTYPE_IEEE802154);
	memset(link_layer_dest, 0xff, ETHER_ADDR_LEN);

	if (m == 0) {
		return 0;
	}
	if ((m->m_flags & M_PKTHDR) == 0) {
		m_freem_list(m);
		return 0;
	}

	sixlowpan_lock();
	ifl = ifnet_get_if6lpan_retained(ifp);

	if (ifl == NULL || if6lpan_flags_ready(ifl) == 0) {
		goto unlock_done;
	}

	/* XXX parent interface equivalent? */
	p_intf = ifl->if6lpan_pifp;
	bpf_func = ifl->if6lpan_bpf_output;

	sixlowpan_unlock();
	if6lpan_release(ifl);

	(void)ifnet_stat_increment_out(ifp, 1, m->m_pkthdr.len, 0);

	/*
	 * We added a 2 byte length before the 802.15.4 data frame
	 * We can play just with the length of the first mbuf in the
	 * chain because bpf_tap_imp() disregards the packet length
	 * of the mbuf packet header.
	 */
	if (bpf_func && (mbuf_setdata(m, m->m_data + 2, m->m_len - 2) == 0)) {
		bpf_func(ifp, m);
		mbuf_setdata(m, m->m_data - 2, m->m_len + 2);
	}

	/* Append ethernet header */
	if ((err = ether_frameout_extended(p_intf, &m, NULL,
	    link_layer_dest, (const char *)&ethertype,
	    NULL, NULL))) {
		return err;
	}

	err = dlil_output(p_intf, PF_802154, m, NULL, NULL, 1, &adv);

	if (err == 0) {
		if (adv.code == FADV_FLOW_CONTROLLED) {
			err = EQFULL;
		} else if (adv.code == FADV_SUSPENDED) {
			err = EQSUSPENDED;
		}
	}
	return err;

unlock_done:
	sixlowpan_unlock();
	if (ifl != NULL) {
		if6lpan_release(ifl);
	}
	m_freem(m);
	return err;
}

/*
 * 6lowpan input routine.
 * Decapsulate the 802.15.4 Data Frame
 * Header decompression on the payload
 * Pass the mbuf to the IPV6 protocol stack using proto_input()
 */
static int
sixlowpan_input(ifnet_t p, __unused protocol_family_t protocol,
    mbuf_t m, __unused char *frame_header)
{
	frame802154_t      ieee02154hdr;
	u_int8_t           *payload = NULL;
	if6lpan_ref        ifl = NULL;
	bpf_packet_func    bpf_func;
	mbuf_t mc, m_temp;
	int off, err = 0;
	u_int16_t len;

	/* Allocate an mbuf cluster for the 802.15.4 frame and uncompressed payload */
	mc = m_getcl(M_WAITOK, MT_DATA, M_PKTHDR);
	if (mc == NULL) {
		err = -1;
		goto err_out;
	}

	memcpy(&len, mtod(m, u_int8_t *), sizeof(u_int16_t));
	len = ntohs(len);
	m_adj(m, sizeof(u_int16_t));
	/* Copy the compressed 802.15.4 payload from source mbuf to allocated cluster mbuf */
	for (m_temp = m, off = 0; m_temp != NULL; m_temp = m_temp->m_next) {
		if (m_temp->m_len > 0) {
			m_copyback(mc, off, m_temp->m_len, mtod(m_temp, void *));
			off += m_temp->m_len;
		}
	}

	p = p_6lowpan_ifnet;
	mc->m_pkthdr.rcvif = p;

	sixlowpan_lock();
	ifl = ifnet_get_if6lpan_retained(p);

	if (ifl == NULL) {
		sixlowpan_unlock();
		err = -1;
		goto err_out;
	}

	if (if6lpan_flags_ready(ifl) == 0) {
		if6lpan_release(ifl);
		sixlowpan_unlock();
		err = -1;
		goto err_out;
	}

	bpf_func = ifl->if6lpan_bpf_input;
	sixlowpan_unlock();
	if6lpan_release(ifl);

	if (bpf_func) {
		bpf_func(p, mc);
	}

	/* Parse the 802.15.4 frame header */
	bzero(&ieee02154hdr, sizeof(ieee02154hdr));
	frame802154_parse(mtod(mc, uint8_t *), len, &ieee02154hdr, &payload);

	/* XXX Add check for your link layer address being dest */
	sixxlowpan_input(&ieee02154hdr, payload);

	if (mbuf_setdata(mc, payload, ieee02154hdr.payload_len)) {
		err = -1;
		goto err_out;
	}
	mbuf_pkthdr_setlen(mc, ieee02154hdr.payload_len);

	/* Post decompression */
	if (proto_input(PF_INET6, mc) != 0) {
		ifnet_stat_increment_in(p, 0, 0, 1);
		err = -1;
		goto err_out;
	} else {
		ifnet_stat_increment_in(p, 1, mc->m_pkthdr.len, 0);
	}

err_out:
	if (err && mc) {
		m_freem(mc);
	}
	if (!err) {
		m_freem(m);
	}
	return err;
}

#define SIXLOWPAN_IFMTU 1280

static int
sixlowpan_config(struct ifnet *ifp, struct ifnet *p)
{
	if6lpan_ref ifl;
	u_int16_t parent_flags;
	sixlowpan_lock();
	ifl = ifnet_get_if6lpan_retained(ifp);
	if (ifl == NULL || ifl->if6lpan_pifp != NULL) {
		sixlowpan_unlock();
		if (ifl != NULL) {
			if6lpan_release(ifl);
		}
		return EBUSY;
	}
	sixlowpan_attach_protocol(p);

	/* set our LL address derived from that of the parent */
	if6lpan_set_addr(ifl, IF_LLADDR(p));
	ifnet_set_lladdr_and_type(ifp, ifl->if6lpan_addr, IEEE802154_ADDR_LEN, IFT_6LOWPAN);

	ifl->if6lpan_pifp = p;
	ifl->if6lpan_flags = 0;
	ifnet_set_mtu(ifp, SIXLOWPAN_IFMTU);
	parent_flags = ifnet_flags(p) & (IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX);
	ifnet_set_flags(ifp, parent_flags, IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX);
	ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);
	ifnet_set_eflags(ifp, IFEF_NOAUTOIPV6LL, IFEF_NOAUTOIPV6LL);
	if6lpan_flags_set_ready(ifl);
	if6lpan_release(ifl);
	sixlowpan_unlock();
	return 0;
}

static int
sixlowpan_unconfig(if6lpan_ref ifl)
{
	struct ifnet *ifp = ifl->if6lpan_ifp;

	sixlowpan_assert_lock_held();
	/* Clear our MAC address. */
	ifnet_set_lladdr_and_type(ifp, NULL, 0, IFT_6LOWPAN);
	sixlowpan_detach_protocol(ifl->if6lpan_pifp);
	ifnet_set_mtu(ifp, 0);
	ifnet_set_flags(ifp, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX | IFF_RUNNING);
	ifnet_set_eflags(ifp, 0, IFEF_NOAUTOIPV6LL);
	ifl->if6lpan_flags = 0;

	return 0;
}

static int
sixlowpan_ioctl(ifnet_t ifp, u_long cmd, void * data)
{
	int             error = 0;
	struct ifreq *  ifr = NULL;
	struct ifnet *  p = NULL;
	struct sixlowpanreq req = {};
	user_addr_t             user_addr = 0;
	if6lpan_ref             ifl = NULL;

	if (ifnet_type(ifp) != IFT_6LOWPAN) {
		return EOPNOTSUPP;
	}
	ifr = (struct ifreq *)data;

	switch (cmd) {
	case SIOCSIFADDR:
		ifnet_set_flags(ifp, IFF_UP, IFF_UP);
		break;

	case SIOCSIF6LOWPAN:
		user_addr = proc_is64bit(current_proc())
		    ? ifr->ifr_data64 : CAST_USER_ADDR_T(ifr->ifr_data);
		error = copyin(user_addr, &req, sizeof(req));
		req.parent[IFNAMSIZ - 1] = '\0';
		if (error) {
			break;
		}
		if (req.parent[0] != '\0') {
			p = ifunit(req.parent);
			if (p == NULL) {
				error = ENXIO;
				break;
			}
			if (ifnet_type(p) != IFT_ETHER
			    && ifnet_type(p) != IFT_IEEE8023ADLAG) {
				error = EPROTONOSUPPORT;
				break;
			}
			error = sixlowpan_config(ifp, p);
			if (error) {
				break;
			}
		}
		break;

	case SIOCGIF6LOWPAN:
		bzero(&req, sizeof req);
		sixlowpan_lock();
		ifl = (if6lpan_ref)ifnet_softc(ifp);
		if (ifl == NULL || if6lpan_flags_detaching(ifl)) {
			sixlowpan_unlock();
			return ifl == NULL ? EOPNOTSUPP : EBUSY;
		}
		p = ifl->if6lpan_pifp;
		sixlowpan_unlock();
		if (p != NULL) {
			snprintf(req.parent, sizeof(req.parent),
			    "%s%d", ifnet_name(p), ifnet_unit(p));
		}
		user_addr = proc_is64bit(current_proc())
		    ? ifr->ifr_data64 : CAST_USER_ADDR_T(ifr->ifr_data);
		error = copyout(&req, user_addr, sizeof(req));
		break;

#ifdef  SIOCSIFMTU /* xxx */
	case SIOCGIFMTU:
		break;

	case SIOCSIFMTU:
		ifnet_set_mtu(ifp, ifr->ifr_mtu);
		break;
#endif /* SIOCSIFMTU */

	default:
		error = EOPNOTSUPP;
	}
	return error;
}

static void
sixlowpan_if_free(struct ifnet * ifp)
{
	if6lpan_ref     ifl;

	if (ifp == NULL) {
		return;
	}
	ifl = (if6lpan_ref)ifnet_softc(ifp);
	if (ifl == NULL) {
		return;
	}
	if6lpan_release(ifl);
	ifnet_release(ifp);
	return;
}

static errno_t
sixlowpan_detached(ifnet_t p, __unused protocol_family_t protocol)
{
	if (ifnet_is_attached(p, 0) == 0) {
		// TODO: Find ifp from the parent p
		// sixlowpan_if_free(ifp);
	}
	return 0;
}

/*
 * Function: sixlowpan_attach_protocol
 * Purpose:
 *   Attach a DLIL protocol to the interface
 *	 The ethernet demux actually special cases 802.15.4.
 *	 The demux here isn't used. The demux will return PF_802154 for the
 *	 appropriate packets and our sixlowpan_input function will be called.
 */
static int
sixlowpan_attach_protocol(struct ifnet *ifp)
{
	int     error;
	struct ifnet_attach_proto_param reg;

	bzero(&reg, sizeof(reg));
	reg.input            = sixlowpan_input;
	reg.detached         = sixlowpan_detached;
	error = ifnet_attach_protocol(ifp, PF_802154, &reg);
	if (error) {
		printf("%s(%s%d) ifnet_attach_protocol failed, %d\n",
		    __func__, ifnet_name(ifp), ifnet_unit(ifp), error);
	}
	return error;
}

/*
 * Function: sixlowpan_detach_protocol
 * Purpose:
 *   Detach our DLIL protocol from an interface
 */
static int
sixlowpan_detach_protocol(struct ifnet *ifp)
{
	int error;

	error = ifnet_detach_protocol(ifp, PF_802154);
	if (error) {
		printf("(%s%d) ifnet_detach_protocol failed, %d\n",
		    ifnet_name(ifp), ifnet_unit(ifp), error);
	}

	return error;
}

static errno_t
sixlowpan_proto_pre_output(ifnet_t ifp,
    __unused protocol_family_t protocol_family,
    mbuf_t *m0,
    const struct sockaddr *dest,
    void *route,
    char *type,
    char *ll_dest)
{
#pragma unused(protocol_family)
	errno_t result = 0;
	struct sockaddr_dl sdl;
	struct sockaddr_in6 *dest6 =  (struct sockaddr_in6 *)(uintptr_t)(size_t)dest;

	if (!IN6_IS_ADDR_MULTICAST(&dest6->sin6_addr)) {
		result = nd6_lookup_ipv6(ifp, dest6, &sdl, sizeof(sdl), route, *m0);
		if (result == 0) {
			bcopy(LLADDR(&sdl), ll_dest, sdl.sdl_alen);
		}
	} else {
		/* map multicast address */
		ll_dest[0] = (dest6->sin6_addr.s6_addr8[14] & 0x1f) | 0x80;
		ll_dest[1] = dest6->sin6_addr.s6_addr8[15];
	}

	/*
	 * XXX This should be generic to the underlying hardware type
	 */
	if (result == 0) {
		u_int16_t ethertype = htons(ETHERTYPE_IEEE802154);
		bcopy(&ethertype, type, sizeof(ethertype));
	}

	return result;
}

static int
sixlowpan_framer_extended(struct ifnet *ifp, struct mbuf **m,
    const struct sockaddr *ndest, const char *edst,
    const char *ether_type, u_int32_t *prepend_len, u_int32_t *postpend_len)
{
#pragma unused(ndest)
#pragma unused(ether_type)
	char buf[IEEE802154_ENCAP_LEN] = {0};
	int buflen = 0, err = 0;
	frame802154_t ieee02154hdr;
	if6lpan_ref ifl = NULL;
	u_int8_t *payload = NULL;
	struct mbuf *mc = NULL;
	u_int16_t len;
	struct sockaddr_in6 *dest6 =  (struct sockaddr_in6 *)(uintptr_t)(size_t)ndest;

	/* Initialize 802.15.4 frame header */
	bzero(&ieee02154hdr, sizeof(ieee02154hdr));
	if (!IN6_IS_ADDR_MULTICAST(&dest6->sin6_addr)) {
		bcopy(edst, ieee02154hdr.dest_addr, sizeof(ieee02154hdr.dest_addr));
		ieee02154hdr.fcf.dest_addr_mode = FRAME802154_LONGADDRMODE;
	} else {
		bcopy(edst, ieee02154hdr.dest_addr, 2);
		ieee02154hdr.fcf.dest_addr_mode = FRAME802154_SHORTADDRMODE;
	}

	/* Allocate a contiguous buffer for IPv6 header & payload */
	/*
	 * XXX As of now either we compress or we don't compress at all
	 * adding another byte of dispatch to communicate that there's no
	 * compression.
	 *
	 * Allocate for the worst case.
	 */
	payload = _MALLOC(m_pktlen(*m) + 1, M_TEMP, M_WAITOK | M_ZERO);
	if (payload == NULL) {
		err = -1;
		goto err_out;
	}

	/* Copy the IPv6 header & payload */
	if (mbuf_copydata(*m, 0, m_pktlen(*m), payload)) {
		err = -1;
		goto err_out;
	}

	/* Allocate an mbuf cluster for the 802.15.4 frame and compressed payload */
	mc = m_getcl(M_WAITOK, MT_DATA, M_PKTHDR);
	if (mc == NULL) {
		err = -1;
		goto err_out;
	}

	sixlowpan_lock();
	ifl = ifnet_get_if6lpan_retained(ifp);
	if (ifl == NULL || if6lpan_flags_ready(ifl) == 0) {
		if (ifl != NULL) {
			if6lpan_release(ifl);
		}
		sixlowpan_unlock();
		err = -1;
		goto err_out;
	}
	bcopy(ifl->if6lpan_addr, ieee02154hdr.src_addr, sizeof(ieee02154hdr.src_addr));
	ieee02154hdr.seq = ifl->if6lpan_ieee802154_seq++;   /**< Sequence number */
	if6lpan_release(ifl);
	sixlowpan_unlock();

	/* Initialize frame control field */
	ieee02154hdr.fcf.frame_type = FRAME802154_DATAFRAME;  /**< 3 bit. Frame type field, see 802.15.4 */
	ieee02154hdr.fcf.security_enabled = 0;  /**< 1 bit. True if security is used in this frame */
	ieee02154hdr.fcf.frame_pending = 0;     /**< 1 bit. True if sender has more data to send */
	ieee02154hdr.fcf.ack_required = 0;      /**< 1 bit. Is an ack frame required? */
	ieee02154hdr.fcf.panid_compression = 0; /**< 1 bit. Is this a compressed header? */
	ieee02154hdr.fcf.frame_version = FRAME802154_IEEE802154_2006; /**< 2 bit. 802.15.4 frame version */
	ieee02154hdr.fcf.src_addr_mode = FRAME802154_LONGADDRMODE;    /**< 2 bit. Source address mode, see 802.15.4 */
	ieee02154hdr.dest_pid = IEEE802154_PANID;   /**< Destination PAN ID */
	ieee02154hdr.src_pid = IEEE802154_PANID;    /**< Source PAN ID */
	ieee02154hdr.payload_len = m_pktlen(*m);    /**< Length of payload field */

	/* Create an 802.15.4 Data header frame */
	buflen = frame802154_create(&ieee02154hdr, (uint8_t *)buf);

	/* Perform inline compression of the IPv6 hdr & payload */
	sixxlowpan_output(&ieee02154hdr, payload);

	/*
	 * Add 2 bytes at the front of the frame indicating the total payload
	 * length
	 */
	len = htons(buflen + ieee02154hdr.payload_len);
	m_copyback(mc, 0, sizeof(len), &len);
	/* Copy back the 802.15.4 Data frame header into mbuf */
	m_copyback(mc, sizeof(len), buflen, buf);
	/* Copy back the compressed payload into mbuf */
	m_copyback(mc, buflen + sizeof(len), ieee02154hdr.payload_len, payload);

	if (prepend_len != NULL) {
		*prepend_len = buflen;
	}
	if (postpend_len != NULL) {
		*postpend_len = 0;
	}

err_out:
	if (payload != NULL) {
		_FREE(payload, M_TEMP);
	}
	m_freem(*m);
	*m = mc;
	return err;
}


static errno_t
sixlowpan_attach_inet6(struct ifnet *ifp, protocol_family_t protocol_family)
{
	struct ifnet_attach_proto_param proto;
	errno_t error;

	bzero(&proto, sizeof(proto));
	proto.pre_output = sixlowpan_proto_pre_output;

	error = ifnet_attach_protocol(ifp, protocol_family, &proto);
	if (error && error != EEXIST) {
		printf("WARNING: %s can't attach ipv6 to %s\n", __func__,
		    if_name(ifp));
	}
	return error;
}

static void
sixlowpan_detach_inet6(struct ifnet *ifp, protocol_family_t protocol_family)
{
	(void) ifnet_detach_protocol(ifp, protocol_family);
}

#if INET6
__private_extern__ int
sixlowpan_family_init(void)
{
	int error = 0;

	error = proto_register_plumber(PF_INET6, IFNET_FAMILY_6LOWPAN,
	    sixlowpan_attach_inet6, sixlowpan_detach_inet6);
	if (error != 0) {
		printf("6lowpan: proto_register_plumber failed for AF_INET6 error=%d\n",
		    error);
		goto done;
	}

	error = sixlowpan_clone_attach();
	if (error != 0) {
		printf("6lowpan: proto_register_plumber failed sixlowpan_clone_attach error=%d\n",
		    error);
		goto done;
	}


done:
	return error;
}
#endif
