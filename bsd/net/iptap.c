/*
 * Copyright (c) 1999-2018 Apple Inc. All rights reserved.
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

#include <kern/locks.h>
#include <kern/zalloc.h>

#include <sys/types.h>
#include <sys/kernel_types.h>
#include <sys/kauth.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/proc.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/net_osdep.h>
#include <net/pktap.h>
#include <net/iptap.h>

#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#define _IP_VHL
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <netinet/ip6.h>
#include <netinet6/in6_pcb.h>

#include <netinet/kpi_ipfilter.h>

#include <libkern/OSAtomic.h>

#include <kern/debug.h>

#include <sys/mcache.h>

#include <string.h>

struct iptap_softc {
	LIST_ENTRY(iptap_softc)         iptap_link;
	uint32_t                                        iptap_unit;
	uint32_t                                        iptap_dlt_raw_count;
	uint32_t                                        iptap_dlt_pkttap_count;
	struct ifnet                            *iptap_ifp;
};

static LIST_HEAD(iptap_list, iptap_softc) iptap_list = LIST_HEAD_INITIALIZER(iptap_list);

static void             iptap_lock_shared(void);
static void             iptap_lock_exclusive(void);
static void             iptap_lock_done(void);
static void             iptap_alloc_lock(void);

decl_lck_rw_data(static, iptap_lck_rw);
static lck_grp_t                *iptap_grp;

errno_t iptap_if_output(ifnet_t, mbuf_t);
errno_t iptap_demux(ifnet_t, mbuf_t, char *, protocol_family_t *);
errno_t iptap_add_proto(ifnet_t, protocol_family_t, const struct ifnet_demux_desc *,
    u_int32_t);
errno_t iptap_del_proto(ifnet_t, protocol_family_t);
errno_t iptap_getdrvspec(ifnet_t, struct ifdrv64 *);
errno_t iptap_ioctl(ifnet_t, unsigned long, void *);
void iptap_detach(ifnet_t);
errno_t iptap_tap_callback(ifnet_t, u_int32_t, bpf_tap_mode );
int iptap_clone_create(struct if_clone *, u_int32_t, void *);
int iptap_clone_destroy(struct ifnet *);

static int iptap_ipf_register(void);
static int iptap_ipf_unregister(void);
static errno_t iptap_ipf_input(void *, mbuf_t *, int, u_int8_t);
static errno_t iptap_ipf_output(void *, mbuf_t *, ipf_pktopts_t);
static void iptap_ipf_detach(void *);

static ipfilter_t iptap_ipf4, iptap_ipf6;

void iptap_bpf_tap(struct mbuf *m, u_int32_t proto, int outgoing);

#define IPTAP_MAXUNIT   IF_MAXUNIT
#define IPTAP_ZONE_MAX_ELEM     MIN(IFNETS_MAX, IPTAP_MAXUNIT)

static struct if_clone iptap_cloner =
    IF_CLONE_INITIALIZER(IPTAP_IFNAME,
    iptap_clone_create,
    iptap_clone_destroy,
    0,
    IPTAP_MAXUNIT,
    IPTAP_ZONE_MAX_ELEM,
    sizeof(struct iptap_softc));

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, OID_AUTO, iptap, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "iptap virtual interface");

static int iptap_total_tap_count = 0;
SYSCTL_INT(_net_link_iptap, OID_AUTO, total_tap_count, CTLFLAG_RD | CTLFLAG_LOCKED,
    &iptap_total_tap_count, 0, "");

static int iptap_log = 0;
SYSCTL_INT(_net_link_iptap, OID_AUTO, log, CTLFLAG_RW | CTLFLAG_LOCKED,
    &iptap_log, 0, "");

#define IPTAP_LOG(fmt, ...) \
do { \
    if ((iptap_log)) \
	printf("%s:%d " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
} while(false)

__private_extern__ void
iptap_init(void)
{
	errno_t error;

	iptap_alloc_lock();

	error = if_clone_attach(&iptap_cloner);
	if (error != 0) {
		panic("%s: if_clone_attach() failed, error %d\n", __func__, error);
	}
}

static void
iptap_alloc_lock(void)
{
	lck_grp_attr_t *grp_attr;
	lck_attr_t *attr;

	grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setdefault(grp_attr);
	iptap_grp = lck_grp_alloc_init(IPTAP_IFNAME, grp_attr);
	lck_grp_attr_free(grp_attr);

	attr = lck_attr_alloc_init();
	lck_attr_setdefault(attr);

	lck_rw_init(&iptap_lck_rw, iptap_grp, attr);
	lck_attr_free(attr);
}

static void
iptap_lock_shared(void)
{
	lck_rw_lock_shared(&iptap_lck_rw);
}

static void
iptap_lock_exclusive(void)
{
	lck_rw_lock_exclusive(&iptap_lck_rw);
}

static void
iptap_lock_done(void)
{
	lck_rw_done(&iptap_lck_rw);
}

__private_extern__ int
iptap_clone_create(struct if_clone *ifc, u_int32_t unit, void *params)
{
#pragma unused(params)

	int error = 0;
	struct iptap_softc *iptap = NULL;
	struct ifnet_init_eparams if_init;

	iptap = if_clone_softc_allocate(&iptap_cloner);
	if (iptap == NULL) {
		printf("%s: _MALLOC failed\n", __func__);
		error = ENOMEM;
		goto done;
	}
	iptap->iptap_unit = unit;

	/*
	 * We do not use a set_bpf_tap() function as we rather rely on the more
	 * accurate callback passed to bpf_attach()
	 */
	bzero(&if_init, sizeof(if_init));
	if_init.ver = IFNET_INIT_CURRENT_VERSION;
	if_init.len = sizeof(if_init);
	if_init.flags = IFNET_INIT_LEGACY;
	if_init.name = ifc->ifc_name;
	if_init.unit = unit;
	if_init.type = IFT_OTHER;
	if_init.family = IFNET_FAMILY_LOOPBACK;
	if_init.output = iptap_if_output;
	if_init.demux = iptap_demux;
	if_init.add_proto = iptap_add_proto;
	if_init.del_proto = iptap_del_proto;
	if_init.softc = iptap;
	if_init.ioctl = iptap_ioctl;
	if_init.detach = iptap_detach;

	error = ifnet_allocate_extended(&if_init, &iptap->iptap_ifp);
	if (error != 0) {
		printf("%s: ifnet_allocate failed, error %d\n", __func__, error);
		goto done;
	}

	ifnet_set_flags(iptap->iptap_ifp, IFF_UP, IFF_UP);

	error = ifnet_attach(iptap->iptap_ifp, NULL);
	if (error != 0) {
		printf("%s: ifnet_attach failed - error %d\n", __func__, error);
		ifnet_release(iptap->iptap_ifp);
		goto done;
	}

	/*
	 * Attach by default as DLT_PKTAP for packet metadata
	 * Provide DLT_RAW for legacy
	 */
	bpf_attach(iptap->iptap_ifp, DLT_PKTAP, sizeof(struct pktap_header), NULL,
	    iptap_tap_callback);
	bpf_attach(iptap->iptap_ifp, DLT_RAW, 0, NULL,
	    iptap_tap_callback);

	/* Take a reference and add to the global list */
	ifnet_reference(iptap->iptap_ifp);

	iptap_lock_exclusive();

	if (LIST_EMPTY(&iptap_list)) {
		iptap_ipf_register();
	}
	LIST_INSERT_HEAD(&iptap_list, iptap, iptap_link);
	iptap_lock_done();
done:
	if (error != 0) {
		if (iptap != NULL) {
			if_clone_softc_deallocate(&iptap_cloner, iptap);
		}
	}
	return error;
}

__private_extern__ int
iptap_clone_destroy(struct ifnet *ifp)
{
	int error = 0;

	(void) ifnet_detach(ifp);

	return error;
}

/*
 * This function is called whenever a DLT is set on the interface:
 * - When interface is attached to a BPF device via BIOCSETIF for the default DLT
 * - Whenever a new DLT is selected via BIOCSDLT
 * - When the interface is detached from a BPF device (direction is zero)
 */
__private_extern__ errno_t
iptap_tap_callback(ifnet_t ifp, u_int32_t dlt, bpf_tap_mode direction)
{
	struct iptap_softc *iptap;

	iptap = ifp->if_softc;
	if (iptap == NULL) {
		printf("%s: if_softc is NULL for ifp %s\n", __func__,
		    ifp->if_xname);
		goto done;
	}
	switch (dlt) {
	case DLT_RAW:
		if (direction == 0) {
			if (iptap->iptap_dlt_raw_count > 0) {
				iptap->iptap_dlt_raw_count--;
				OSAddAtomic(-1, &iptap_total_tap_count);
			}
		} else {
			iptap->iptap_dlt_raw_count++;
			OSAddAtomic(1, &iptap_total_tap_count);
		}
		break;
	case DLT_PKTAP:
		if (direction == 0) {
			if (iptap->iptap_dlt_pkttap_count > 0) {
				iptap->iptap_dlt_pkttap_count--;
				OSAddAtomic(-1, &iptap_total_tap_count);
			}
		} else {
			iptap->iptap_dlt_pkttap_count++;
			OSAddAtomic(1, &iptap_total_tap_count);
		}
		break;
	}
done:
	/*
	 * Attachements count must be positive and we're in trouble
	 * if we have more that 2**31 attachements
	 */
	VERIFY(iptap_total_tap_count >= 0);

	return 0;
}

__private_extern__ errno_t
iptap_if_output(ifnet_t ifp, mbuf_t m)
{
#pragma unused(ifp)

	mbuf_freem(m);
	return ENOTSUP;
}

__private_extern__ errno_t
iptap_demux(ifnet_t ifp, mbuf_t m, char *header,
    protocol_family_t *ppf)
{
#pragma unused(ifp)
#pragma unused(m)
#pragma unused(header)
#pragma unused(ppf)

	return ENOTSUP;
}

__private_extern__ errno_t
iptap_add_proto(ifnet_t ifp, protocol_family_t pf,
    const struct ifnet_demux_desc *dmx, u_int32_t cnt)
{
#pragma unused(ifp)
#pragma unused(pf)
#pragma unused(dmx)
#pragma unused(cnt)

	return 0;
}

__private_extern__ errno_t
iptap_del_proto(ifnet_t ifp, protocol_family_t pf)
{
#pragma unused(ifp)
#pragma unused(pf)

	return 0;
}

__private_extern__ errno_t
iptap_getdrvspec(ifnet_t ifp, struct ifdrv64 *ifd)
{
	errno_t error = 0;
	struct iptap_softc *iptap;

	iptap = ifp->if_softc;
	if (iptap == NULL) {
		error = ENOENT;
		printf("%s: iptap NULL - error %d\n", __func__, error);
		goto done;
	}

	switch (ifd->ifd_cmd) {
	case PKTP_CMD_TAP_COUNT: {
		uint32_t tap_count = iptap->iptap_dlt_raw_count + iptap->iptap_dlt_pkttap_count;

		if (ifd->ifd_len < sizeof(tap_count)) {
			printf("%s: PKTP_CMD_TAP_COUNT ifd_len %llu too small - error %d\n",
			    __func__, ifd->ifd_len, error);
			error = EINVAL;
			break;
		}
		error = copyout(&tap_count, ifd->ifd_data, sizeof(tap_count));
		if (error) {
			printf("%s: PKTP_CMD_TAP_COUNT copyout - error %d\n", __func__, error);
			goto done;
		}
		break;
	}
	default:
		error = EINVAL;
		break;
	}

done:
	return error;
}

__private_extern__ errno_t
iptap_ioctl(ifnet_t ifp, unsigned long cmd, void *data)
{
	errno_t error = 0;

	if ((cmd & IOC_IN)) {
		error = kauth_authorize_generic(kauth_cred_get(), KAUTH_GENERIC_ISSUSER);
		if (error) {
			goto done;
		}
	}

	switch (cmd) {
	case SIOCGDRVSPEC32: {
		struct ifdrv64 ifd;
		struct ifdrv32 *ifd32 = (struct ifdrv32 *)data;

		memcpy(ifd.ifd_name, ifd32->ifd_name, sizeof(ifd.ifd_name));
		ifd.ifd_cmd = ifd32->ifd_cmd;
		ifd.ifd_len = ifd32->ifd_len;
		ifd.ifd_data = ifd32->ifd_data;

		error = iptap_getdrvspec(ifp, &ifd);

		break;
	}
	case SIOCGDRVSPEC64: {
		struct ifdrv64 *ifd64 = (struct ifdrv64 *)data;

		error = iptap_getdrvspec(ifp, ifd64);

		break;
	}
	default:
		error = ENOTSUP;
		break;
	}
done:
	return error;
}

__private_extern__ void
iptap_detach(ifnet_t ifp)
{
	struct iptap_softc *iptap = NULL;

	iptap_lock_exclusive();

	iptap = ifp->if_softc;
	ifp->if_softc = NULL;
	LIST_REMOVE(iptap, iptap_link);

	if (LIST_EMPTY(&iptap_list)) {
		iptap_ipf_unregister();
	}

	iptap_lock_done();

	/* Drop reference as it's no more on the global list */
	ifnet_release(ifp);
	if_clone_softc_deallocate(&iptap_cloner, iptap);

	/* This is for the reference taken by ifnet_attach() */
	(void) ifnet_release(ifp);
}

static int
iptap_ipf_register(void)
{
	struct ipf_filter iptap_ipfinit;
	int err = 0;

	IPTAP_LOG("\n");

	bzero(&iptap_ipfinit, sizeof(iptap_ipfinit));
	iptap_ipfinit.name = IPTAP_IFNAME;
	iptap_ipfinit.cookie = &iptap_ipf4;
	iptap_ipfinit.ipf_input = iptap_ipf_input;
	iptap_ipfinit.ipf_output = iptap_ipf_output;
	iptap_ipfinit.ipf_detach = iptap_ipf_detach;

	err = ipf_addv4(&iptap_ipfinit, &iptap_ipf4);
	if (err != 0) {
		printf("%s: ipf_addv4 for %s0 failed - %d\n",
		    __func__, IPTAP_IFNAME, err);
		goto done;
	}

	iptap_ipfinit.cookie = &iptap_ipf6;
	err = ipf_addv6(&iptap_ipfinit, &iptap_ipf6);
	if (err != 0) {
		printf("%s: ipf_addv6 for %s0 failed - %d\n",
		    __func__, IPTAP_IFNAME, err);
		(void) ipf_remove(iptap_ipf4);
		iptap_ipf4 = NULL;
		goto done;
	}

done:
	return err;
}

static int
iptap_ipf_unregister(void)
{
	int err = 0;

	IPTAP_LOG("\n");

	if (iptap_ipf4 != NULL) {
		err = ipf_remove(iptap_ipf4);
		if (err != 0) {
			printf("%s: ipf_remove (ipv4) for %s0 failed - %d\n",
			    __func__, IPTAP_IFNAME, err);
			goto done;
		}
		iptap_ipf4 = NULL;
	}

	if (iptap_ipf6 != NULL) {
		err = ipf_remove(iptap_ipf6);
		if (err != 0) {
			printf("%s: ipf_remove (ipv6) for %s0 failed - %d\n",
			    __func__, IPTAP_IFNAME, err);
			goto done;
		}
		iptap_ipf6 = NULL;
	}
done:
	return err;
}

static errno_t
iptap_ipf_input(void *arg, mbuf_t *mp, int off, u_int8_t proto)
{
#pragma unused(off)
#pragma unused(proto)

	if (arg == (void *)&iptap_ipf4) {
		iptap_bpf_tap(*mp, AF_INET, 0);
	} else if (arg == (void *)&iptap_ipf6) {
		iptap_bpf_tap(*mp, AF_INET6, 0);
	} else {
		IPTAP_LOG("%s:%d bad cookie 0x%llx &iptap_ipf4 0x%llx "
		    "&iptap_ipf6 0x%llx\n", __func__, __LINE__,
		    (uint64_t)VM_KERNEL_ADDRPERM(arg),
		    (uint64_t)VM_KERNEL_ADDRPERM(&iptap_ipf4),
		    (uint64_t)VM_KERNEL_ADDRPERM(&iptap_ipf6));
	}

	return 0;
}

static errno_t
iptap_ipf_output(void *arg, mbuf_t *mp, ipf_pktopts_t opt)
{
#pragma unused(opt)

	if (arg == (void *)&iptap_ipf4) {
		iptap_bpf_tap(*mp, AF_INET, 1);
	} else if (arg == (void *)&iptap_ipf6) {
		iptap_bpf_tap(*mp, AF_INET6, 1);
	} else {
		IPTAP_LOG("%s:%d bad cookie 0x%llx &iptap_ipf4 0x%llx "
		    "&iptap_ipf6 0x%llx\n", __func__, __LINE__,
		    (uint64_t)VM_KERNEL_ADDRPERM(arg),
		    (uint64_t)VM_KERNEL_ADDRPERM(&iptap_ipf4),
		    (uint64_t)VM_KERNEL_ADDRPERM(&iptap_ipf6));
	}

	return 0;
}

static void
iptap_ipf_detach(void *arg)
{
#pragma unused(arg)
}

__private_extern__ void
iptap_bpf_tap(struct mbuf *m, u_int32_t proto, int outgoing)
{
	struct iptap_softc *iptap;
	void (*bpf_tap_func)(ifnet_t, u_int32_t, mbuf_t, void *, size_t ) =
	    outgoing ? bpf_tap_out : bpf_tap_in;
	uint16_t src_scope_id = 0;
	uint16_t dst_scope_id = 0;

	if (proto == AF_INET6) {
		struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
		/*
		 * Clear the embedded scope ID
		 */
		if (IN6_IS_SCOPE_EMBED(&ip6->ip6_src)) {
			src_scope_id = ip6->ip6_src.s6_addr16[1];
			ip6->ip6_src.s6_addr16[1] = 0;
		}
		if (IN6_IS_SCOPE_EMBED(&ip6->ip6_dst)) {
			dst_scope_id = ip6->ip6_dst.s6_addr16[1];
			ip6->ip6_dst.s6_addr16[1] = 0;
		}
	}

	iptap_lock_shared();

	LIST_FOREACH(iptap, &iptap_list, iptap_link) {
		if (iptap->iptap_dlt_raw_count > 0) {
			bpf_tap_func(iptap->iptap_ifp, DLT_RAW, m,
			    NULL, 0);
		}
		if (iptap->iptap_dlt_pkttap_count > 0) {
			struct {
				struct pktap_header hdr;
				u_int32_t proto;
			} hdr_buffer;
			struct pktap_header *hdr = &hdr_buffer.hdr;
			size_t hdr_size = sizeof(hdr_buffer);
			struct ifnet *ifp = outgoing ? NULL : m->m_pkthdr.rcvif;

			/* Verify the structure is packed */
			_CASSERT(sizeof(hdr_buffer) == sizeof(struct pktap_header) + sizeof(u_int32_t));

			bzero(hdr, sizeof(hdr_buffer));
			hdr->pth_length = sizeof(struct pktap_header);
			hdr->pth_type_next = PTH_TYPE_PACKET;
			hdr->pth_dlt = DLT_NULL;
			if (ifp != NULL) {
				snprintf(hdr->pth_ifname, sizeof(hdr->pth_ifname), "%s",
				    ifp->if_xname);
			}
			hdr_buffer.proto = proto;
			hdr->pth_flags = outgoing ? PTH_FLAG_DIR_OUT : PTH_FLAG_DIR_IN;
			hdr->pth_protocol_family = proto;
			hdr->pth_frame_pre_length = 0;
			hdr->pth_frame_post_length = 0;
			hdr->pth_iftype = ifp != NULL ? ifp->if_type : 0;
			hdr->pth_ifunit = ifp != NULL ? ifp->if_unit : 0;

			pktap_fill_proc_info(hdr, proto, m, 0, outgoing, ifp);

			hdr->pth_svc = so_svc2tc(m->m_pkthdr.pkt_svc);

			bpf_tap_func(iptap->iptap_ifp, DLT_PKTAP, m, hdr, hdr_size);
		}
	}

	iptap_lock_done();

	if (proto == AF_INET6) {
		struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);

		/*
		 * Restore the embedded scope ID
		 */
		if (IN6_IS_SCOPE_EMBED(&ip6->ip6_src)) {
			ip6->ip6_src.s6_addr16[1] = src_scope_id;
		}
		if (IN6_IS_SCOPE_EMBED(&ip6->ip6_dst)) {
			ip6->ip6_dst.s6_addr16[1] = dst_scope_id;
		}
	}
}
