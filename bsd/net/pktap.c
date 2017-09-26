/*
 * Copyright (c) 2012-2017 Apple Inc. All rights reserved.
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

#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#define	_IP_VHL
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <netinet/ip6.h>
#include <netinet6/in6_pcb.h>

#include <libkern/OSAtomic.h>

#include <kern/debug.h>

#include <sys/mcache.h>

#include <string.h>

extern struct inpcbinfo ripcbinfo;

struct pktap_softc {
	LIST_ENTRY(pktap_softc)		pktp_link;
	uint32_t					pktp_unit;
	uint32_t					pktp_dlt_raw_count;
	uint32_t					pktp_dlt_pkttap_count;
	struct ifnet				*pktp_ifp;
	struct pktap_filter			pktp_filters[PKTAP_MAX_FILTERS];
};

#ifndef PKTAP_DEBUG
#define	PKTAP_DEBUG 0
#endif /* PKTAP_DEBUG */

#define	PKTAP_FILTER_OK	0		/* Packet passes filter checks */
#define	PKTAP_FILTER_SKIP 1		/* Do not tap this packet */

static int pktap_inited = 0;

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, IFT_PKTAP, pktap,
    CTLFLAG_RW  |CTLFLAG_LOCKED, 0, "pktap virtual interface");

uint32_t pktap_total_tap_count = 0;
SYSCTL_UINT(_net_link_pktap, OID_AUTO, total_tap_count,
    CTLFLAG_RD | CTLFLAG_LOCKED, &pktap_total_tap_count, 0, "");

static u_int64_t pktap_count_unknown_if_type = 0;
SYSCTL_QUAD(_net_link_pktap, OID_AUTO, count_unknown_if_type,
    CTLFLAG_RD | CTLFLAG_LOCKED, &pktap_count_unknown_if_type, "");

static int pktap_log = 0;
SYSCTL_INT(_net_link_pktap, OID_AUTO, log,
    CTLFLAG_RW | CTLFLAG_LOCKED, &pktap_log, 0, "");

#define	PKTAP_LOG(mask, fmt, ...) \
do { \
	if ((pktap_log & mask)) \
		printf("%s:%d " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
} while (false)

#define	PKTP_LOG_FUNC 0x01
#define	PKTP_LOG_FILTER 0x02
#define	PKTP_LOG_INPUT 0x04
#define	PKTP_LOG_OUTPUT 0x08
#define	PKTP_LOG_ERROR 0x10
#define	PKTP_LOG_NOPCB 0x20

/*
 * pktap_lck_rw protects the global list of pktap interfaces
 */
decl_lck_rw_data(static, pktap_lck_rw_data);
static lck_rw_t *pktap_lck_rw = &pktap_lck_rw_data;
static lck_grp_t *pktap_lck_grp = NULL;
static lck_attr_t *pktap_lck_attr = NULL;

static LIST_HEAD(pktap_list, pktap_softc) pktap_list =
    LIST_HEAD_INITIALIZER(pktap_list);

int pktap_clone_create(struct if_clone *, u_int32_t, void *);
int pktap_clone_destroy(struct ifnet *);

static struct if_clone pktap_cloner =
	IF_CLONE_INITIALIZER(PKTAP_IFNAME,
		pktap_clone_create,
		pktap_clone_destroy,
		0,
		IF_MAXUNIT);

errno_t pktap_if_output(ifnet_t, mbuf_t);
errno_t pktap_demux(ifnet_t, mbuf_t, char *, protocol_family_t *);
errno_t pktap_add_proto(ifnet_t, protocol_family_t,
	const struct ifnet_demux_desc *, u_int32_t);
errno_t pktap_del_proto(ifnet_t, protocol_family_t);
errno_t pktap_getdrvspec(ifnet_t, struct ifdrv64 *);
errno_t pktap_setdrvspec(ifnet_t, struct ifdrv64 *);
errno_t pktap_ioctl(ifnet_t, unsigned long, void *);
void pktap_detach(ifnet_t);
int pktap_filter_evaluate(struct pktap_softc *, struct ifnet *);
void pktap_bpf_tap(struct ifnet *, protocol_family_t, struct mbuf *,
    u_int32_t, u_int32_t, int);
errno_t pktap_tap_callback(ifnet_t, u_int32_t, bpf_tap_mode);

static void
pktap_hexdump(int mask, void *addr, size_t len)
{
	unsigned char *buf = addr;
	size_t i;

	if (!(pktap_log & mask))
		return;

	for (i = 0; i < len; i++) {
		unsigned char  h = (buf[i] & 0xf0) >> 4;
		unsigned char  l = buf[i] & 0x0f;

		if (i != 0) {
			if (i % 32 == 0)
				printf("\n");
			else if (i % 4 == 0)
				printf(" ");
		}
		printf("%c%c",
			h < 10 ? h + '0' : h - 10 + 'a',
			l < 10 ? l + '0' : l - 10 + 'a');
	}
	if (i % 32 != 0)
		printf("\n");
}

__private_extern__ void
pktap_init(void)
{
	int error = 0;
	lck_grp_attr_t *lck_grp_attr = NULL;

	/* Make sure we're called only once */
	VERIFY(pktap_inited == 0);

	pktap_inited = 1;

	lck_grp_attr = lck_grp_attr_alloc_init();
	pktap_lck_grp = lck_grp_alloc_init("pktap", lck_grp_attr);
	pktap_lck_attr = lck_attr_alloc_init();
#if PKTAP_DEBUG
	lck_attr_setdebug(pktap_lck_attr);
#endif /* PKTAP_DEBUG */
	lck_rw_init(pktap_lck_rw, pktap_lck_grp, pktap_lck_attr);
	lck_grp_attr_free(lck_grp_attr);

	LIST_INIT(&pktap_list);

	error = if_clone_attach(&pktap_cloner);
	if (error != 0)
		panic("%s: if_clone_attach() failed, error %d\n",
		    __func__, error);
}

__private_extern__ int
pktap_clone_create(struct if_clone *ifc, u_int32_t unit, __unused void *params)
{
	int error = 0;
	struct pktap_softc *pktap = NULL;
	struct ifnet_init_eparams if_init;

	PKTAP_LOG(PKTP_LOG_FUNC, "unit %u\n", unit);

	pktap = _MALLOC(sizeof(struct pktap_softc), M_DEVBUF,
	    M_WAITOK | M_ZERO);
	if (pktap == NULL) {
		printf("%s: _MALLOC failed\n", __func__);
		error = ENOMEM;
		goto done;
	}
	pktap->pktp_unit = unit;

	/*
	 * By default accept packet from physical interfaces
	 */
	pktap->pktp_filters[0].filter_op = PKTAP_FILTER_OP_PASS;
	pktap->pktp_filters[0].filter_param = PKTAP_FILTER_PARAM_IF_TYPE;
	pktap->pktp_filters[0].filter_param_if_type = IFT_ETHER;

#if CONFIG_EMBEDDED
	pktap->pktp_filters[1].filter_op = PKTAP_FILTER_OP_PASS;
	pktap->pktp_filters[1].filter_param = PKTAP_FILTER_PARAM_IF_TYPE;
	pktap->pktp_filters[1].filter_param_if_type = IFT_CELLULAR;
#else /* CONFIG_EMBEDDED */
	pktap->pktp_filters[1].filter_op = PKTAP_FILTER_OP_PASS;
	pktap->pktp_filters[1].filter_param = PKTAP_FILTER_PARAM_IF_TYPE;
	pktap->pktp_filters[1].filter_param_if_type = IFT_IEEE1394;
#endif /* CONFIG_EMBEDDED */

#if (DEVELOPMENT || DEBUG)
	pktap->pktp_filters[2].filter_op = PKTAP_FILTER_OP_PASS;
	pktap->pktp_filters[2].filter_param = PKTAP_FILTER_PARAM_IF_TYPE;
	pktap->pktp_filters[2].filter_param_if_type = IFT_OTHER;
#endif /* DEVELOPMENT || DEBUG */

	/*
	 * We do not use a set_bpf_tap() function as we rather rely on the more
	 * accurate callback passed to bpf_attach()
	 */
	bzero(&if_init, sizeof(if_init));
	if_init.ver = IFNET_INIT_CURRENT_VERSION;
	if_init.len = sizeof (if_init);
	if_init.flags = IFNET_INIT_LEGACY;
	if_init.name = ifc->ifc_name;
	if_init.unit = unit;
	if_init.type = IFT_PKTAP;
	if_init.family = IFNET_FAMILY_LOOPBACK;
	if_init.output = pktap_if_output;
	if_init.demux = pktap_demux;
	if_init.add_proto = pktap_add_proto;
	if_init.del_proto = pktap_del_proto;
	if_init.softc = pktap;
	if_init.ioctl = pktap_ioctl;
	if_init.detach = pktap_detach;

	error = ifnet_allocate_extended(&if_init, &pktap->pktp_ifp);
	if (error != 0) {
		printf("%s: ifnet_allocate failed, error %d\n",
		    __func__, error);
		goto done;
	}

	ifnet_set_flags(pktap->pktp_ifp, IFF_UP, IFF_UP);

	error = ifnet_attach(pktap->pktp_ifp, NULL);
	if (error != 0) {
		printf("%s: ifnet_attach failed - error %d\n", __func__, error);
		ifnet_release(pktap->pktp_ifp);
		goto done;
	}

	/* Attach DLT_PKTAP as the default DLT */
	bpf_attach(pktap->pktp_ifp, DLT_PKTAP, sizeof(struct pktap_header),
	    NULL, pktap_tap_callback);
	bpf_attach(pktap->pktp_ifp, DLT_RAW, 0, NULL, pktap_tap_callback);

	/* Take a reference and add to the global list */
	ifnet_reference(pktap->pktp_ifp);
	lck_rw_lock_exclusive(pktap_lck_rw);
	LIST_INSERT_HEAD(&pktap_list, pktap, pktp_link);
	lck_rw_done(pktap_lck_rw);
done:
	if (error != 0) {
		if (pktap != NULL)
			_FREE(pktap, M_DEVBUF);
	}
	return (error);
}

__private_extern__ int
pktap_clone_destroy(struct ifnet *ifp)
{
	int error = 0;

	PKTAP_LOG(PKTP_LOG_FUNC, "%s\n", ifp->if_xname);

	(void) ifnet_detach(ifp);

	return (error);
}

/*
 * This function is called whenever a DLT is set on the interface:
 * - When interface is attached to a BPF device via BIOCSETIF for the
 *   default DLT
 * - Whenever a new DLT is selected via BIOCSDLT
 * - When the interface is detached from a BPF device (direction is zero)
 */
__private_extern__ errno_t
pktap_tap_callback(ifnet_t ifp, u_int32_t dlt, bpf_tap_mode direction)
{
	struct pktap_softc *pktap;

	pktap = ifp->if_softc;
	if (pktap == NULL) {
		printf("%s: if_softc is NULL for ifp %s\n", __func__,
		    ifp->if_xname);
		goto done;
	}
	switch (dlt) {
		case DLT_RAW:
			if (direction == 0) {
				if (pktap->pktp_dlt_raw_count > 0) {
					pktap->pktp_dlt_raw_count--;
					OSAddAtomic(-1, &pktap_total_tap_count);

				}
			} else {
				pktap->pktp_dlt_raw_count++;
				OSAddAtomic(1, &pktap_total_tap_count);
			}
			break;
		case DLT_PKTAP:
			if (direction == 0) {
				if (pktap->pktp_dlt_pkttap_count > 0) {
					pktap->pktp_dlt_pkttap_count--;
					OSAddAtomic(-1, &pktap_total_tap_count);
				}
			} else {
				pktap->pktp_dlt_pkttap_count++;
				OSAddAtomic(1, &pktap_total_tap_count);
			}
			break;
	}
done:
	/*
	 * Attachements count must be positive and we're in trouble
	 * if we have more that 2**31 attachements
	 */
	VERIFY(pktap_total_tap_count >= 0);

	return (0);
}

__private_extern__ errno_t
pktap_if_output(ifnet_t ifp, mbuf_t m)
{
	PKTAP_LOG(PKTP_LOG_FUNC, "%s\n", ifp->if_xname);
	mbuf_freem(m);
	return (ENOTSUP);
}

__private_extern__ errno_t
pktap_demux(ifnet_t ifp, __unused mbuf_t m, __unused char *header,
	__unused protocol_family_t *ppf)
{
	PKTAP_LOG(PKTP_LOG_FUNC, "%s\n", ifp->if_xname);
	return (ENOTSUP);
}

__private_extern__ errno_t
pktap_add_proto(__unused ifnet_t ifp, protocol_family_t pf,
    __unused const struct ifnet_demux_desc *dmx, __unused u_int32_t cnt)
{
	PKTAP_LOG(PKTP_LOG_FUNC, "%s pf %u\n", ifp->if_xname, pf);
	return (0);
}

__private_extern__ errno_t
pktap_del_proto(__unused ifnet_t ifp, __unused protocol_family_t pf)
{
	PKTAP_LOG(PKTP_LOG_FUNC, "%s pf %u\n", ifp->if_xname, pf);
	return (0);
}

__private_extern__ errno_t
pktap_getdrvspec(ifnet_t ifp, struct ifdrv64 *ifd)
{
	errno_t error = 0;
	struct pktap_softc *pktap;
	int i;

	PKTAP_LOG(PKTP_LOG_FUNC, "%s\n", ifp->if_xname);

	pktap = ifp->if_softc;
	if (pktap == NULL) {
		error = ENOENT;
		printf("%s: pktap NULL - error %d\n", __func__, error);
		goto done;
	}

	switch (ifd->ifd_cmd) {
	case PKTP_CMD_FILTER_GET: {
		struct x_pktap_filter x_filters[PKTAP_MAX_FILTERS];

		bzero(&x_filters, sizeof(x_filters));

		if (ifd->ifd_len < PKTAP_MAX_FILTERS * sizeof(struct x_pktap_filter)) {
			printf("%s: PKTP_CMD_FILTER_GET ifd_len %llu too small - error %d\n",
				__func__, ifd->ifd_len, error);
			error = EINVAL;
			break;
		}
		for (i = 0; i < PKTAP_MAX_FILTERS; i++) {
			struct pktap_filter *pktap_filter = pktap->pktp_filters + i;
			struct x_pktap_filter *x_filter = x_filters + i;

			x_filter->filter_op = pktap_filter->filter_op;
			x_filter->filter_param = pktap_filter->filter_param;

			if (pktap_filter->filter_param == PKTAP_FILTER_PARAM_IF_TYPE)
				x_filter->filter_param_if_type = pktap_filter->filter_param_if_type;
			else if (pktap_filter->filter_param == PKTAP_FILTER_PARAM_IF_NAME)
				strlcpy(x_filter->filter_param_if_name,
						pktap_filter->filter_param_if_name,
						sizeof(x_filter->filter_param_if_name));
		}
		error = copyout(x_filters, ifd->ifd_data,
			PKTAP_MAX_FILTERS * sizeof(struct x_pktap_filter));
		if (error) {
			printf("%s: PKTP_CMD_FILTER_GET copyout - error %d\n", __func__, error);
			goto done;
		}
		break;
	}
	case PKTP_CMD_TAP_COUNT: {
		uint32_t tap_count = pktap->pktp_dlt_raw_count + pktap->pktp_dlt_pkttap_count;

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
	return (error);
}

__private_extern__ errno_t
pktap_setdrvspec(ifnet_t ifp, struct ifdrv64 *ifd)
{
	errno_t error = 0;
	struct pktap_softc *pktap;

	PKTAP_LOG(PKTP_LOG_FUNC, "%s\n", ifp->if_xname);

	pktap = ifp->if_softc;
	if (pktap == NULL) {
		error = ENOENT;
		printf("%s: pktap NULL - error %d\n", __func__, error);
		goto done;
	}

	switch (ifd->ifd_cmd) {
	case PKTP_CMD_FILTER_SET: {
		struct x_pktap_filter user_filters[PKTAP_MAX_FILTERS];
		int i;
		int got_op_none = 0;

		if (ifd->ifd_len != PKTAP_MAX_FILTERS * sizeof(struct x_pktap_filter)) {
			printf("%s: PKTP_CMD_FILTER_SET bad ifd_len %llu - error %d\n",
				__func__, ifd->ifd_len, error);
			error = EINVAL;
			break;
		}
		error = copyin(ifd->ifd_data, &user_filters, ifd->ifd_len);
		if (error) {
			printf("%s: copyin - error %d\n", __func__, error);
			goto done;
		}
		/*
		 * Validate user provided parameters
		 */
		for (i = 0; i < PKTAP_MAX_FILTERS; i++) {
			struct x_pktap_filter *x_filter = user_filters + i;

			switch (x_filter->filter_op) {
				case PKTAP_FILTER_OP_NONE:
					/* Following entries must be PKTAP_FILTER_OP_NONE */
					got_op_none = 1;
					break;
				case PKTAP_FILTER_OP_PASS:
				case PKTAP_FILTER_OP_SKIP:
					/* Invalid after PKTAP_FILTER_OP_NONE */
					if (got_op_none) {
						error = EINVAL;
						break;
					}
					break;
				default:
					error = EINVAL;
					break;
			}
			if (error != 0)
				break;

			switch (x_filter->filter_param) {
				case PKTAP_FILTER_OP_NONE:
					if (x_filter->filter_op != PKTAP_FILTER_OP_NONE) {
						error = EINVAL;
						break;
					}
					break;

				/*
				 * Do not allow to tap a pktap from a pktap
				 */
				case PKTAP_FILTER_PARAM_IF_TYPE:
					if (x_filter->filter_param_if_type == IFT_PKTAP ||
						x_filter->filter_param_if_type > 0xff) {
						error = EINVAL;
						break;
					}
					break;

				case PKTAP_FILTER_PARAM_IF_NAME:
					if (strncmp(x_filter->filter_param_if_name, PKTAP_IFNAME,
							strlen(PKTAP_IFNAME)) == 0) {
						error = EINVAL;
						break;
					}
					break;

				default:
					error = EINVAL;
					break;
			}
			if (error != 0)
				break;
		}
		if (error != 0)
			break;
		for (i = 0; i < PKTAP_MAX_FILTERS; i++) {
			struct pktap_filter *pktap_filter = pktap->pktp_filters + i;
			struct x_pktap_filter *x_filter = user_filters + i;

			pktap_filter->filter_op = x_filter->filter_op;
			pktap_filter->filter_param = x_filter->filter_param;

			if (pktap_filter->filter_param == PKTAP_FILTER_PARAM_IF_TYPE)
				pktap_filter->filter_param_if_type = x_filter->filter_param_if_type;
			else if (pktap_filter->filter_param == PKTAP_FILTER_PARAM_IF_NAME) {
				size_t len;

				strlcpy(pktap_filter->filter_param_if_name,
						x_filter->filter_param_if_name,
						sizeof(pktap_filter->filter_param_if_name));
				/*
				 * If name does not end with a number then it's a "wildcard" match
				 * where we compare the prefix of the interface name
				 */
				len = strlen(pktap_filter->filter_param_if_name);
				if (pktap_filter->filter_param_if_name[len] < '0' ||
					pktap_filter->filter_param_if_name[len] > '9')
					pktap_filter->filter_ifname_prefix_len = len;
			}
		}
		break;
	}
	default:
		error = EINVAL;
		break;
	}

done:
	return (error);
}

__private_extern__ errno_t
pktap_ioctl(ifnet_t ifp, unsigned long cmd, void *data)
{
	errno_t error = 0;

	PKTAP_LOG(PKTP_LOG_FUNC, "%s\n", ifp->if_xname);

	if ((cmd & IOC_IN)) {
		error = kauth_authorize_generic(kauth_cred_get(), KAUTH_GENERIC_ISSUSER);
		if (error) {
			PKTAP_LOG(PKTP_LOG_ERROR,
				"%s: kauth_authorize_generic(KAUTH_GENERIC_ISSUSER) - error %d\n",
				__func__, error);
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

		error = pktap_getdrvspec(ifp, &ifd);

		break;
	}
	case SIOCGDRVSPEC64: {
		struct ifdrv64 *ifd64 = (struct ifdrv64 *)data;

		error = pktap_getdrvspec(ifp, ifd64);

		break;
	}
	case SIOCSDRVSPEC32: {
		struct ifdrv64 ifd;
		struct ifdrv32 *ifd32 = (struct ifdrv32 *)data;

		memcpy(ifd.ifd_name, ifd32->ifd_name, sizeof(ifd.ifd_name));
		ifd.ifd_cmd = ifd32->ifd_cmd;
		ifd.ifd_len = ifd32->ifd_len;
		ifd.ifd_data = ifd32->ifd_data;

		error = pktap_setdrvspec(ifp, &ifd);
		break;
	}
	case SIOCSDRVSPEC64: {
		struct ifdrv64 *ifd64 = (struct ifdrv64 *)data;

		error = pktap_setdrvspec(ifp, ifd64);

		break;
	}
	default:
		error = ENOTSUP;
		break;
	}
done:
	return (error);
}

__private_extern__ void
pktap_detach(ifnet_t ifp)
{
	struct pktap_softc *pktap;

	PKTAP_LOG(PKTP_LOG_FUNC, "%s\n", ifp->if_xname);

	lck_rw_lock_exclusive(pktap_lck_rw);

	pktap = ifp->if_softc;
	ifp->if_softc = NULL;
	LIST_REMOVE(pktap, pktp_link);

	lck_rw_done(pktap_lck_rw);

	/* Drop reference as it's no more on the global list */
	ifnet_release(ifp);

	_FREE(pktap, M_DEVBUF);

	/* This is for the reference taken by ifnet_attach() */
	(void) ifnet_release(ifp);
}

__private_extern__ int
pktap_filter_evaluate(struct pktap_softc *pktap, struct ifnet *ifp)
{
	int i;
	int result = PKTAP_FILTER_SKIP; /* Need positive matching rule to pass */
	int match = 0;

	for (i = 0; i < PKTAP_MAX_FILTERS; i++) {
		struct pktap_filter *pktap_filter = pktap->pktp_filters + i;
		size_t len = pktap_filter->filter_ifname_prefix_len != 0 ?
			pktap_filter->filter_ifname_prefix_len : PKTAP_IFXNAMESIZE;

		switch (pktap_filter->filter_op) {
			case PKTAP_FILTER_OP_NONE:
				match = 1;
				break;

			case PKTAP_FILTER_OP_PASS:
				if (pktap_filter->filter_param == PKTAP_FILTER_PARAM_IF_TYPE) {
					if (pktap_filter->filter_param_if_type == 0 ||
						ifp->if_type == pktap_filter->filter_param_if_type) {
						result = PKTAP_FILTER_OK;
						match = 1;
						PKTAP_LOG(PKTP_LOG_FILTER, "pass %s match type %u\n",
							ifp->if_xname, pktap_filter->filter_param_if_type);
						break;
					}
				}
				if (pktap_filter->filter_param == PKTAP_FILTER_PARAM_IF_NAME) {
					if (strncmp(ifp->if_xname, pktap_filter->filter_param_if_name,
							len) == 0) {
						result = PKTAP_FILTER_OK;
						match = 1;
						PKTAP_LOG(PKTP_LOG_FILTER, "pass %s match name %s\n",
							ifp->if_xname, pktap_filter->filter_param_if_name);
						break;
					}
				}
				break;

			case PKTAP_FILTER_OP_SKIP:
				if (pktap_filter->filter_param == PKTAP_FILTER_PARAM_IF_TYPE) {
					if (pktap_filter->filter_param_if_type == 0 ||
						ifp->if_type == pktap_filter->filter_param_if_type) {
						result = PKTAP_FILTER_SKIP;
						match = 1;
						PKTAP_LOG(PKTP_LOG_FILTER, "skip %s match type %u\n",
							ifp->if_xname, pktap_filter->filter_param_if_type);
						break;
					}
				}
				if (pktap_filter->filter_param == PKTAP_FILTER_PARAM_IF_NAME) {
					if (strncmp(ifp->if_xname, pktap_filter->filter_param_if_name,
							len) == 0) {
						result = PKTAP_FILTER_SKIP;
						match = 1;
						PKTAP_LOG(PKTP_LOG_FILTER, "skip %s match name %s\n",
							ifp->if_xname, pktap_filter->filter_param_if_name);
						break;
					}
				}
				break;
		}
		if (match)
			break;
	}

	if (match == 0) {
		PKTAP_LOG(PKTP_LOG_FILTER, "%s no match\n",
			ifp->if_xname);
	}
	return (result);
}

static void
pktap_set_procinfo(struct pktap_header *hdr, struct so_procinfo *soprocinfo)
{
	hdr->pth_pid = soprocinfo->spi_pid;
	proc_name(soprocinfo->spi_pid, hdr->pth_comm, MAXCOMLEN);
	if (soprocinfo->spi_pid != 0)
		uuid_copy(hdr->pth_uuid, soprocinfo->spi_uuid);

	/*
	 * When not delegated, the effective pid is the same as the real pid
	 */
	if (soprocinfo->spi_delegated != 0) {
		hdr->pth_flags |= PTH_FLAG_PROC_DELEGATED;
		hdr->pth_epid = soprocinfo->spi_epid;
		proc_name(soprocinfo->spi_epid, hdr->pth_ecomm, MAXCOMLEN);
		uuid_copy(hdr->pth_euuid, soprocinfo->spi_euuid);
	}
}

__private_extern__ void
pktap_finalize_proc_info(struct pktap_header *hdr)
{
	int found;
	struct so_procinfo soprocinfo;

	if (!(hdr->pth_flags & PTH_FLAG_DELAY_PKTAP))
		return;

	/*
	 * Clear the flag as it's internal
	 */
	hdr->pth_flags &= ~PTH_FLAG_DELAY_PKTAP;

	if (hdr->pth_ipproto == IPPROTO_TCP)
		found = inp_findinpcb_procinfo(&tcbinfo, hdr->pth_flowid,
		    &soprocinfo);
	else if (hdr->pth_ipproto == IPPROTO_UDP)
		found = inp_findinpcb_procinfo(&udbinfo, hdr->pth_flowid,
		    &soprocinfo);
	else
		found = inp_findinpcb_procinfo(&ripcbinfo, hdr->pth_flowid,
		    &soprocinfo);

	if (found == 1)
		pktap_set_procinfo(hdr, &soprocinfo);
}

__private_extern__ void
pktap_fill_proc_info(struct pktap_header *hdr, protocol_family_t proto,
	struct mbuf *m, u_int32_t pre, int outgoing, struct ifnet *ifp)
{
	int found = 0;
	struct so_procinfo soprocinfo;

	/*
	 * Getting the pid and procname is expensive
	 * For outgoing, do the lookup only if there's an
	 * associated socket as indicated by the flowhash
	 */
	if (outgoing != 0 && m->m_pkthdr.pkt_flowsrc == FLOWSRC_INPCB) {
		/*
		 * To avoid lock ordering issues we delay the process lookup
		 * to the BPF read as we cannot
		 * assume the socket lock is unlocked on output
		 */
		found = 0;
		hdr->pth_flags |= PTH_FLAG_DELAY_PKTAP;
		hdr->pth_flowid = m->m_pkthdr.pkt_flowid;
		if (m->m_pkthdr.pkt_flags & PKTF_FLOW_RAWSOCK)
			hdr->pth_ipproto = IPPROTO_RAW;
		else		
			hdr->pth_ipproto = m->m_pkthdr.pkt_proto;
		if (m->m_pkthdr.pkt_flags & PKTF_NEW_FLOW)
			hdr->pth_flags |= PTH_FLAG_NEW_FLOW;
	} else if (outgoing == 0) {
		struct inpcb *inp = NULL;

		if (proto == PF_INET) {
			struct ip ip;
			errno_t error;
			size_t hlen;
			struct in_addr faddr, laddr;
			u_short fport = 0, lport = 0;
			struct inpcbinfo *pcbinfo = NULL;
			int wildcard = 0;

			error = mbuf_copydata(m, pre, sizeof(struct ip), &ip);
			if (error != 0) {
				PKTAP_LOG(PKTP_LOG_ERROR,
				    "mbuf_copydata tcp v4 failed for %s\n",
				    hdr->pth_ifname);
				goto done;
			}
			hlen = IP_VHL_HL(ip.ip_vhl) << 2;

			faddr = ip.ip_src;
			laddr = ip.ip_dst;

			if (ip.ip_p == IPPROTO_TCP) {
				struct tcphdr th;

				error = mbuf_copydata(m, pre + hlen,
					sizeof(struct tcphdr), &th);
				if (error != 0)
					goto done;

				fport = th.th_sport;
				lport = th.th_dport;

				pcbinfo = &tcbinfo;
			} else if (ip.ip_p == IPPROTO_UDP) {
				struct udphdr uh;

				error = mbuf_copydata(m, pre + hlen,
					sizeof(struct udphdr), &uh);
				if (error != 0) {
					PKTAP_LOG(PKTP_LOG_ERROR,
					    "mbuf_copydata udp v4 failed for %s\n",
					    hdr->pth_ifname);
					goto done;
				}
				fport = uh.uh_sport;
				lport = uh.uh_dport;

				pcbinfo = &udbinfo;
				wildcard = 1;
			}
			if (pcbinfo != NULL) {
				inp = in_pcblookup_hash(pcbinfo, faddr, fport,
					laddr, lport, wildcard, outgoing ? NULL : ifp);

				if (inp == NULL && hdr->pth_iftype != IFT_LOOP)
					PKTAP_LOG(PKTP_LOG_NOPCB,
					    "in_pcblookup_hash no pcb %s\n",
					    hdr->pth_ifname);
			} else {
				PKTAP_LOG(PKTP_LOG_NOPCB,
				    "unknown ip_p %u on %s\n",
				    ip.ip_p, hdr->pth_ifname);
				pktap_hexdump(PKTP_LOG_NOPCB, &ip, sizeof(struct ip));
			}
		} else if (proto == PF_INET6) {
			struct ip6_hdr ip6;
			errno_t error;
			struct in6_addr *faddr;
			struct in6_addr *laddr;
			u_short fport = 0, lport = 0;
			struct inpcbinfo *pcbinfo = NULL;
			int wildcard = 0;

			error = mbuf_copydata(m, pre, sizeof(struct ip6_hdr), &ip6);
			if (error != 0)
				goto done;

			faddr = &ip6.ip6_src;
			laddr = &ip6.ip6_dst;

			if (ip6.ip6_nxt == IPPROTO_TCP) {
				struct tcphdr th;

				error = mbuf_copydata(m, pre + sizeof(struct ip6_hdr),
					sizeof(struct tcphdr), &th);
				if (error != 0) {
					PKTAP_LOG(PKTP_LOG_ERROR,
					    "mbuf_copydata tcp v6 failed for %s\n",
					    hdr->pth_ifname);
					goto done;
				}

				fport = th.th_sport;
				lport = th.th_dport;

				pcbinfo = &tcbinfo;
			} else if (ip6.ip6_nxt == IPPROTO_UDP) {
				struct udphdr uh;

				error = mbuf_copydata(m, pre + sizeof(struct ip6_hdr),
					sizeof(struct udphdr), &uh);
				if (error != 0) {
					PKTAP_LOG(PKTP_LOG_ERROR,
					    "mbuf_copydata udp v6 failed for %s\n",
					    hdr->pth_ifname);
					goto done;
				}

				fport = uh.uh_sport;
				lport = uh.uh_dport;

				pcbinfo = &udbinfo;
				wildcard = 1;
			}
			if (pcbinfo != NULL) {
				inp = in6_pcblookup_hash(pcbinfo, faddr, fport,
					laddr, lport, wildcard, outgoing ? NULL : ifp);

				if (inp == NULL && hdr->pth_iftype != IFT_LOOP)
					PKTAP_LOG(PKTP_LOG_NOPCB,
					    "in6_pcblookup_hash no pcb %s\n",
					    hdr->pth_ifname);
			} else {
				PKTAP_LOG(PKTP_LOG_NOPCB,
				    "unknown ip6.ip6_nxt %u on %s\n",
				    ip6.ip6_nxt, hdr->pth_ifname);
				pktap_hexdump(PKTP_LOG_NOPCB, &ip6, sizeof(struct ip6_hdr));
			}
		}
		if (inp != NULL) {
			if (inp->inp_state != INPCB_STATE_DEAD && inp->inp_socket != NULL) {
				found = 1;
				inp_get_soprocinfo(inp, &soprocinfo);
			}
			in_pcb_checkstate(inp, WNT_RELEASE, 0);
		}
	}
done:
	/*
	 * -1 means PID not found
	 */
	hdr->pth_pid = -1;
	hdr->pth_epid = -1;
	if (found != 0)
		pktap_set_procinfo(hdr, &soprocinfo);
}

__private_extern__ void
pktap_bpf_tap(struct ifnet *ifp, protocol_family_t proto, struct mbuf *m,
    u_int32_t pre, u_int32_t post, int outgoing)
{
	struct pktap_softc *pktap;
	void (*bpf_tap_func)(ifnet_t, u_int32_t, mbuf_t, void *, size_t) =
		outgoing ? bpf_tap_out : bpf_tap_in;

	lck_rw_lock_shared(pktap_lck_rw);

	/*
	 * No need to take the ifnet_lock as the struct ifnet field if_bpf is
	 * protected by the BPF subsystem
	 */
	LIST_FOREACH(pktap, &pktap_list, pktp_link) {
		int filter_result;

		filter_result = pktap_filter_evaluate(pktap, ifp);
		if (filter_result == PKTAP_FILTER_SKIP)
			continue;

		if (pktap->pktp_dlt_raw_count > 0) {
			/* We accept only IPv4 and IPv6 packets for the raw DLT */
			if ((proto == AF_INET ||proto == AF_INET6) &&
				!(m->m_pkthdr.pkt_flags & PKTF_INET_RESOLVE)) {
				/*
				 * We can play just with the length of the first mbuf in the
				 * chain because bpf_tap_imp() disregard the packet length
				 * of the mbuf packet header.
				 */
				if (mbuf_setdata(m, m->m_data + pre,  m->m_len - pre) == 0) {
					bpf_tap_func(pktap->pktp_ifp, DLT_RAW, m, NULL, 0);
					mbuf_setdata(m, m->m_data - pre, m->m_len + pre);
				}
			}
		}

		if (pktap->pktp_dlt_pkttap_count > 0) {
			struct {
				struct pktap_header hdr;
				u_int32_t proto;
			} hdr_buffer;
			struct pktap_header *hdr = &hdr_buffer.hdr;
			size_t hdr_size = sizeof(struct pktap_header);
			int unknown_if_type = 0;
			size_t data_adjust = 0;
			u_int32_t pre_adjust = 0;

			/* Verify the structure is packed */
			_CASSERT(sizeof(hdr_buffer) == sizeof(struct pktap_header) + sizeof(u_int32_t));

			bzero(&hdr_buffer, sizeof(hdr_buffer));
			hdr->pth_length = sizeof(struct pktap_header);
			hdr->pth_type_next = PTH_TYPE_PACKET;

			/*
			 * Set DLT of packet based on interface type
			 */
			switch (ifp->if_type) {
				case IFT_LOOP:
				case IFT_GIF:
				case IFT_STF:
				case IFT_CELLULAR:
					/*
					 * Packets from pdp interfaces have no loopback
					 * header that contain the protocol number.
					 * As BPF just concatenate the header and the
					 * packet content in a single buffer,
					 * stash the protocol after the pktap header
					 * and adjust the size of the header accordingly
					 */
					hdr->pth_dlt = DLT_NULL;
					if (pre == 0) {
						hdr_buffer.proto = proto;
						hdr_size = sizeof(hdr_buffer);
						pre_adjust = sizeof(hdr_buffer.proto);
					}
					break;
				case IFT_ETHER:
				case IFT_BRIDGE:
				case IFT_L2VLAN:
				case IFT_IEEE8023ADLAG:
					hdr->pth_dlt = DLT_EN10MB;
					break;
				case IFT_PPP:
					hdr->pth_dlt = DLT_PPP;
					break;
				case IFT_IEEE1394:
					hdr->pth_dlt = DLT_APPLE_IP_OVER_IEEE1394;
					break;
				case IFT_OTHER:
					if (strncmp(ifp->if_name, "utun", strlen("utun")) == 0) {
						/*
						 * For utun:
						 * - incoming packets do not have the prefix set to four
						 * - some packets are as small as two bytes!
						 */
						if (m_pktlen(m) < 4)
							goto done;
						if (proto != AF_INET && proto != AF_INET6)
							goto done;
						if (proto == AF_INET && (size_t) m_pktlen(m) - 4 < sizeof(struct ip))
							goto done;
						if (proto == AF_INET6 && (size_t) m_pktlen(m) - 4 < sizeof(struct ip6_hdr))
							goto done;

						/*
						 * Handle two cases:
						 * - The old utun encapsulation with the protocol family in network order
						 * - A raw IPv4 or IPv6 packet
						 */
						uint8_t data = *(uint8_t *)mbuf_data(m);
						if ((data >> 4) == 4 || (data >> 4) == 6) {
							pre = 4;
						} else {
							/*
							 * Skip the protocol in the mbuf as it's in network order
							 */
							pre = 4;
							data_adjust = 4;
						}
					}
					hdr->pth_dlt = DLT_NULL;
					hdr_buffer.proto = proto;
					hdr_size = sizeof(hdr_buffer);
					break;
				default:
					if (pre == 0)
						hdr->pth_dlt = DLT_RAW;
					else
						unknown_if_type = 1;
					break;
			}
			if (unknown_if_type) {
				PKTAP_LOG(PKTP_LOG_FUNC,
				    "unknown if_type %u for %s\n",
				    ifp->if_type, ifp->if_xname);
				pktap_count_unknown_if_type += 1;
			} else {
				strlcpy(hdr->pth_ifname, ifp->if_xname,
				    sizeof(hdr->pth_ifname));
				hdr->pth_flags |= outgoing ? PTH_FLAG_DIR_OUT : PTH_FLAG_DIR_IN;
				hdr->pth_protocol_family = proto;
				hdr->pth_frame_pre_length = pre + pre_adjust;
				hdr->pth_frame_post_length = post;
				hdr->pth_iftype = ifp->if_type;
				hdr->pth_ifunit = ifp->if_unit;

				pktap_fill_proc_info(hdr, proto, m, pre, outgoing, ifp);

				hdr->pth_svc = so_svc2tc(m->m_pkthdr.pkt_svc);

				if (data_adjust == 0) {
					bpf_tap_func(pktap->pktp_ifp, DLT_PKTAP, m, hdr, hdr_size);
				} else {
					/*
					 * We can play just with the length of the first mbuf in the
					 * chain because bpf_tap_imp() disregard the packet length
					 * of the mbuf packet header.
					 */
					if (mbuf_setdata(m, m->m_data + data_adjust,  m->m_len - data_adjust) == 0) {
						bpf_tap_func(pktap->pktp_ifp, DLT_PKTAP, m, hdr, hdr_size);
						mbuf_setdata(m, m->m_data - data_adjust, m->m_len + data_adjust);
					}
				}
			}
		}
	}
done:
	lck_rw_done(pktap_lck_rw);
}

__private_extern__ void
pktap_input(struct ifnet *ifp, protocol_family_t proto, struct mbuf *m,
    char *frame_header)
{
	char *hdr;
	char *start;

	/* Fast path */
	if (pktap_total_tap_count == 0)
		return;

	hdr = (char *)mbuf_data(m);
	start = (char *)mbuf_datastart(m);
	/* Make sure the frame header is fully contained in the  mbuf */
	if (frame_header != NULL && frame_header >= start && frame_header <= hdr) {
		size_t o_len = m->m_len;
		u_int32_t pre = hdr - frame_header;

		if (mbuf_setdata(m, frame_header, o_len + pre) == 0) {
			PKTAP_LOG(PKTP_LOG_INPUT, "ifp %s proto %u pre %u post %u\n",
				ifp->if_xname, proto, pre, 0);

			pktap_bpf_tap(ifp, proto, m,  pre, 0, 0);
			mbuf_setdata(m, hdr, o_len);
		}
	} else {
		PKTAP_LOG(PKTP_LOG_INPUT, "ifp %s proto %u pre %u post %u\n",
			ifp->if_xname, proto, 0, 0);

		pktap_bpf_tap(ifp, proto, m, 0, 0, 0);
	}
}

__private_extern__ void
pktap_output(struct ifnet *ifp, protocol_family_t proto, struct mbuf *m,
    u_int32_t pre, u_int32_t post)
{
	/* Fast path */
	if (pktap_total_tap_count == 0)
		return;

	PKTAP_LOG(PKTP_LOG_OUTPUT, "ifp %s proto %u pre %u post %u\n",
		ifp->if_xname, proto, pre, post);

	pktap_bpf_tap(ifp, proto, m, pre, post, 1);
}

