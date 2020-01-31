/*
 * Copyright (c) 2015-2016 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http: www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * THEORY OF OPERATION
 *
 * The packet mangler subsystem provides a limited way for user space
 * applications to apply certain actions on certain flows.
 *
 * A user space applications opens a kernel control socket with the name
 * PACKET_MANGLER_CONTROL_NAME to attach to the packet mangler subsystem.
 * When connected, a "struct packet_mangler" is created and set as the
 * "unitinfo" of the corresponding kernel control socket instance.
 * Connect call for packet mangler's kernel control socket also registers
 * ip filers with cookie set to the packet_mangler instance.
 * The ip filters are removed when control socket is disconnected.
 */
#include <sys/types.h>
#include <sys/kern_control.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/syslog.h>

#include <kern/locks.h>
#include <kern/zalloc.h>
#include <kern/debug.h>

#include <net/packet_mangler.h>

#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/ip.h>
#include <netinet/kpi_ipfilter.h>
#include <string.h>
#include <libkern/libkern.h>

#define MAX_PACKET_MANGLER                      1

#define PKT_MNGLR_FLG_IPFILTER_ATTACHED         0x00000001

SYSCTL_NODE(_net, OID_AUTO, pktmnglr, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "pktmnglr");
SYSCTL_INT(_net_pktmnglr, OID_AUTO, log, CTLFLAG_RW | CTLFLAG_LOCKED,
    &pkt_mnglr_log_level, 0, "");
/*
 * The structure packet_mangler represents a user space packet filter
 * It's created and associated with a kernel control socket instance
 */
struct packet_mangler {
	kern_ctl_ref                    pkt_mnglr_kcref;
	uint32_t                        pkt_mnglr_kcunit;
	uint32_t                        pkt_mnglr_flags;
	/* IP filter related params */
	ipfilter_t                      pkt_mnglr_ipfref;
	ipfilter_t                      pkt_mnglr_ipfrefv6;
	struct ipf_filter               pkt_mnglr_ipfilter;

	/* Options */
	uint8_t                         activate;
	Pkt_Mnglr_Flow                  dir;
	struct sockaddr_storage         lsaddr;
	struct sockaddr_storage         rsaddr;
	struct sockaddr_storage         swap_lsaddr;
	struct sockaddr_storage         swap_rsaddr;
	uint32_t                        ip_action_mask;
	uint16_t                        lport;
	uint16_t                        rport;
	uint32_t                        proto;
	uint32_t                        proto_action_mask;
};

/* Array of all the packet mangler instancesi */
struct packet_mangler **packet_manglers = NULL;

uint32_t pkt_mnglr_active_count = 0;    /* Number of active packet filters */
uint32_t pkt_mnglr_close_wait_timeout = 1000; /* in milliseconds */

static kern_ctl_ref pkt_mnglr_kctlref = NULL;

static lck_grp_attr_t *pkt_mnglr_lck_grp_attr = NULL;
static lck_attr_t *pkt_mnglr_lck_attr = NULL;
static lck_grp_t *pkt_mnglr_lck_grp = NULL;

/* The lock below protects packet_manglers DS, packet_mangler DS */
decl_lck_rw_data(static, pkt_mnglr_lck_rw);

#define PKT_MNGLR_RW_LCK_MAX    8

int pkt_mnglr_rw_nxt_lck = 0;
void* pkt_mnglr_rw_lock_history[PKT_MNGLR_RW_LCK_MAX];

int pkt_mnglr_rw_nxt_unlck = 0;
void* pkt_mnglr_rw_unlock_history[PKT_MNGLR_RW_LCK_MAX];


#define PACKET_MANGLER_ZONE_NAME        "packet_mangler"
#define PACKET_MANGLER_ZONE_MAX         10
static struct zone *packet_mangler_zone = NULL; /* zone for packet_mangler */

/*
 * For troubleshooting
 */
int pkt_mnglr_log_level = LOG_ERR;
int pkt_mnglr_debug = 1;

/*
 * Forward declaration to appease the compiler
 */
static void pkt_mnglr_rw_lock_exclusive(lck_rw_t *);
static void pkt_mnglr_rw_unlock_exclusive(lck_rw_t *);
static void pkt_mnglr_rw_lock_shared(lck_rw_t *);
static void pkt_mnglr_rw_unlock_shared(lck_rw_t *);

static errno_t pktmnglr_ipfilter_output(void *cookie, mbuf_t *data,
    ipf_pktopts_t options);
static errno_t pktmnglr_ipfilter_input(void *cookie, mbuf_t *data,
    int offset, u_int8_t protocol);
static void pktmnglr_ipfilter_detach(void *cookie);

static void chksm_update(mbuf_t data);

#define TCP_OPT_MULTIPATH_TCP   30
#define MPTCP_SBT_VER_OFFSET    2

#define MPTCP_SUBTYPE_MPCAPABLE         0x0
#define MPTCP_SUBTYPE_MPJOIN            0x1
#define MPTCP_SUBTYPE_DSS               0x2
#define MPTCP_SUBTYPE_ADD_ADDR          0x3
#define MPTCP_SUBTYPE_REM_ADDR          0x4
#define MPTCP_SUBTYPE_MP_PRIO           0x5
#define MPTCP_SUBTYPE_MP_FAIL           0x6
#define MPTCP_SUBTYPE_MP_FASTCLOSE      0x7

/*
 * packet filter global read write lock
 */

static void
pkt_mnglr_rw_lock_exclusive(lck_rw_t *lck)
{
	void *lr_saved;

	lr_saved = __builtin_return_address(0);

	lck_rw_lock_exclusive(lck);

	pkt_mnglr_rw_lock_history[pkt_mnglr_rw_nxt_lck] = lr_saved;
	pkt_mnglr_rw_nxt_lck =
	    (pkt_mnglr_rw_nxt_lck + 1) % PKT_MNGLR_RW_LCK_MAX;
}

static void
pkt_mnglr_rw_unlock_exclusive(lck_rw_t *lck)
{
	void *lr_saved;

	lr_saved = __builtin_return_address(0);

	lck_rw_unlock_exclusive(lck);

	pkt_mnglr_rw_unlock_history[pkt_mnglr_rw_nxt_unlck] =
	    lr_saved;
	pkt_mnglr_rw_nxt_unlck = (pkt_mnglr_rw_nxt_unlck + 1) % PKT_MNGLR_RW_LCK_MAX;
}

static void
pkt_mnglr_rw_lock_shared(lck_rw_t *lck)
{
	void *lr_saved;

	lr_saved = __builtin_return_address(0);

	lck_rw_lock_shared(lck);

	pkt_mnglr_rw_lock_history[pkt_mnglr_rw_nxt_lck] = lr_saved;
	pkt_mnglr_rw_nxt_lck = (pkt_mnglr_rw_nxt_lck + 1) % PKT_MNGLR_RW_LCK_MAX;
}

static void
pkt_mnglr_rw_unlock_shared(lck_rw_t *lck)
{
	void *lr_saved;

	lr_saved = __builtin_return_address(0);

	lck_rw_unlock_shared(lck);

	pkt_mnglr_rw_unlock_history[pkt_mnglr_rw_nxt_unlck] = lr_saved;
	pkt_mnglr_rw_nxt_unlck = (pkt_mnglr_rw_nxt_unlck + 1) % PKT_MNGLR_RW_LCK_MAX;
}

/*
 * Packet Mangler's Kernel control socket callbacks
 */
static errno_t
pkt_mnglr_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac,
    void **unitinfo)
{
	errno_t error = 0;
	struct packet_mangler *p_pkt_mnglr = NULL;

	PKT_MNGLR_LOG(LOG_NOTICE, "Connecting packet mangler filter.");

	p_pkt_mnglr = zalloc(packet_mangler_zone);
	if (p_pkt_mnglr == NULL) {
		PKT_MNGLR_LOG(LOG_ERR, "zalloc failed");
		error = ENOMEM;
		goto done;
	}

	bzero(p_pkt_mnglr, sizeof(struct packet_mangler));

	pkt_mnglr_rw_lock_exclusive(&pkt_mnglr_lck_rw);
	if (packet_manglers == NULL) {
		struct packet_mangler **tmp;

		pkt_mnglr_rw_unlock_exclusive(&pkt_mnglr_lck_rw);

		MALLOC(tmp,
		    struct packet_mangler **,
		    MAX_PACKET_MANGLER * sizeof(struct packet_mangler *),
		    M_TEMP,
		    M_WAITOK | M_ZERO);

		pkt_mnglr_rw_lock_exclusive(&pkt_mnglr_lck_rw);

		if (tmp == NULL && packet_manglers == NULL) {
			error = ENOMEM;
			pkt_mnglr_rw_unlock_exclusive(&pkt_mnglr_lck_rw);
			goto done;
		}
		/* Another thread may have won the race */
		if (packet_manglers != NULL) {
			FREE(tmp, M_TEMP);
		} else {
			packet_manglers = tmp;
		}
	}

	if (sac->sc_unit == 0 || sac->sc_unit > MAX_PACKET_MANGLER) {
		PKT_MNGLR_LOG(LOG_ERR, "bad sc_unit %u", sac->sc_unit);
		error = EINVAL;
	} else if (packet_manglers[sac->sc_unit - 1] != NULL) {
		PKT_MNGLR_LOG(LOG_ERR, "sc_unit %u in use", sac->sc_unit);
		error = EADDRINUSE;
	} else {
		/*
		 * kernel control socket kcunit numbers start at 1
		 */
		packet_manglers[sac->sc_unit - 1] = p_pkt_mnglr;

		p_pkt_mnglr->pkt_mnglr_kcref = kctlref;
		p_pkt_mnglr->pkt_mnglr_kcunit = sac->sc_unit;

		*unitinfo = p_pkt_mnglr;
		pkt_mnglr_active_count++;
	}

	p_pkt_mnglr->pkt_mnglr_ipfilter.cookie = p_pkt_mnglr;
	p_pkt_mnglr->pkt_mnglr_ipfilter.name = "com.apple.pktmnglripfilter";
	p_pkt_mnglr->pkt_mnglr_ipfilter.ipf_input = pktmnglr_ipfilter_input;
	p_pkt_mnglr->pkt_mnglr_ipfilter.ipf_output = pktmnglr_ipfilter_output;
	p_pkt_mnglr->pkt_mnglr_ipfilter.ipf_detach = pktmnglr_ipfilter_detach;
	error = ipf_addv4(&(p_pkt_mnglr->pkt_mnglr_ipfilter), &(p_pkt_mnglr->pkt_mnglr_ipfref));
	if (error) {
		PKT_MNGLR_LOG(LOG_ERR, "Could not register packet mangler's IPv4 Filter");
		goto done;
	}
	error = ipf_addv6(&(p_pkt_mnglr->pkt_mnglr_ipfilter), &(p_pkt_mnglr->pkt_mnglr_ipfrefv6));
	if (error) {
		ipf_remove(p_pkt_mnglr->pkt_mnglr_ipfref);
		PKT_MNGLR_LOG(LOG_ERR, "Could not register packet mangler's IPv6 Filter");
		goto done;
	}

	PKT_MNGLR_LOG(LOG_INFO, "Registered packet mangler's IP Filters");
	p_pkt_mnglr->pkt_mnglr_flags |= PKT_MNGLR_FLG_IPFILTER_ATTACHED;
	pkt_mnglr_rw_unlock_exclusive(&pkt_mnglr_lck_rw);

done:
	if (error != 0 && p_pkt_mnglr != NULL) {
		zfree(packet_mangler_zone, p_pkt_mnglr);
	}

	PKT_MNGLR_LOG(LOG_INFO, "return %d pkt_mnglr_active_count %u kcunit %u",
	    error, pkt_mnglr_active_count, sac->sc_unit);

	return error;
}

static errno_t
pkt_mnglr_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t kcunit, void *unitinfo)
{
#pragma unused(kctlref)
	errno_t error = 0;
	struct packet_mangler *p_pkt_mnglr;

	PKT_MNGLR_LOG(LOG_INFO, "Disconnecting packet mangler kernel control");

	if (packet_manglers == NULL) {
		PKT_MNGLR_LOG(LOG_ERR, "no packet filter");
		error = EINVAL;
		goto done;
	}
	if (kcunit > MAX_PACKET_MANGLER) {
		PKT_MNGLR_LOG(LOG_ERR, "kcunit %u > MAX_PACKET_MANGLER (%d)",
		    kcunit, MAX_PACKET_MANGLER);
		error = EINVAL;
		goto done;
	}

	p_pkt_mnglr = (struct packet_mangler *)unitinfo;
	if (p_pkt_mnglr == NULL) {
		PKT_MNGLR_LOG(LOG_ERR, "Unit info is NULL");
		goto done;
	}

	pkt_mnglr_rw_lock_exclusive(&pkt_mnglr_lck_rw);
	if (packet_manglers[kcunit - 1] != p_pkt_mnglr || p_pkt_mnglr->pkt_mnglr_kcunit != kcunit) {
		PKT_MNGLR_LOG(LOG_ERR, "bad unit info %u)",
		    kcunit);
		pkt_mnglr_rw_unlock_exclusive(&pkt_mnglr_lck_rw);
		goto done;
	}

	/*
	 * Make filter inactive
	 */
	packet_manglers[kcunit - 1] = NULL;
	pkt_mnglr_active_count--;
	if (p_pkt_mnglr->pkt_mnglr_flags & PKT_MNGLR_FLG_IPFILTER_ATTACHED) {
		(void) ipf_remove(p_pkt_mnglr->pkt_mnglr_ipfref);
		(void) ipf_remove(p_pkt_mnglr->pkt_mnglr_ipfrefv6);
	}
	pkt_mnglr_rw_unlock_exclusive(&pkt_mnglr_lck_rw);
	zfree(packet_mangler_zone, p_pkt_mnglr);
done:
	PKT_MNGLR_LOG(LOG_INFO, "return %d pkt_mnglr_active_count %u kcunit %u",
	    error, pkt_mnglr_active_count, kcunit);

	return error;
}

static errno_t
pkt_mnglr_ctl_getopt(kern_ctl_ref kctlref, u_int32_t kcunit, void *unitinfo,
    int opt, void *data, size_t *len)
{
#pragma unused(kctlref, opt)
	errno_t error = 0;
	struct packet_mangler *p_pkt_mnglr = (struct packet_mangler *)unitinfo;

	PKT_MNGLR_LOG(LOG_NOTICE, "");

	pkt_mnglr_rw_lock_shared(&pkt_mnglr_lck_rw);

	if (packet_manglers == NULL) {
		PKT_MNGLR_LOG(LOG_ERR, "no packet filter");
		error = EINVAL;
		goto done;
	}
	if (kcunit > MAX_PACKET_MANGLER) {
		PKT_MNGLR_LOG(LOG_ERR, "kcunit %u > MAX_PACKET_MANGLER (%d)",
		    kcunit, MAX_PACKET_MANGLER);
		error = EINVAL;
		goto done;
	}
	if (p_pkt_mnglr != (void *)packet_manglers[kcunit - 1]) {
		PKT_MNGLR_LOG(LOG_ERR, "unitinfo does not match for kcunit %u",
		    kcunit);
		error = EINVAL;
		goto done;
	}
	switch (opt) {
	case PKT_MNGLR_OPT_PROTO_ACT_MASK:
		if (*len < sizeof(uint32_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_PROTO_ACT_MASK "
			    "len too small %lu", *len);
			error = EINVAL;
			goto done;
		}

		if (data != NULL) {
			*(uint32_t *)data = p_pkt_mnglr->proto_action_mask;
		}
		break;
	case PKT_MNGLR_OPT_IP_ACT_MASK:
		if (*len < sizeof(uint32_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_IP_ACT_MASK "
			    "len too small %lu", *len);
			error = EINVAL;
			goto done;
		}

		if (data != NULL) {
			*(uint32_t *)data = p_pkt_mnglr->ip_action_mask;
		}
		break;
	case PKT_MNGLR_OPT_LOCAL_IP:
		if (*len < sizeof(struct sockaddr_storage)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_LOCAL_IP "
			    "len too small %lu", *len);
			error = EINVAL;
			goto done;
		}

		if (data != NULL) {
			*(struct sockaddr_storage *)data = p_pkt_mnglr->lsaddr;
		}
		break;
	case PKT_MNGLR_OPT_REMOTE_IP:
		if (*len < sizeof(struct sockaddr_storage)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_REMOTE_IP "
			    "len too small %lu", *len);
			error = EINVAL;
			goto done;
		}

		if (data != NULL) {
			*(struct sockaddr_storage *)data = p_pkt_mnglr->rsaddr;
		}
		break;
	case PKT_MNGLR_OPT_LOCAL_PORT:
		if (*len < sizeof(uint16_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_LOCAL_PORT "
			    "len too small %lu", *len);
			error = EINVAL;
			goto done;
		}

		if (data != NULL) {
			*(uint16_t *)data = p_pkt_mnglr->lport;
		}
		break;
	case PKT_MNGLR_OPT_REMOTE_PORT:
		if (*len < sizeof(uint16_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_REMOTE_PORT "
			    "len too small %lu", *len);
			error = EINVAL;
			goto done;
		}

		if (data != NULL) {
			*(uint16_t *)data = p_pkt_mnglr->rport;
		}
		break;
	case PKT_MNGLR_OPT_DIRECTION:
		if (*len < sizeof(uint32_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_DIRECTION "
			    "len too small %lu", *len);
			error = EINVAL;
			goto done;
		}
		if (data != NULL) {
			*(uint32_t *)data = p_pkt_mnglr->dir;
		}
		break;
	case PKT_MNGLR_OPT_PROTOCOL:
		if (*len < sizeof(uint32_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_PROTOCOL "
			    "len too small %lu", *len);
			error = EINVAL;
			goto done;
		}
		if (data != NULL) {
			*(uint32_t *)data = p_pkt_mnglr->proto;
		}
		break;
	case PKT_MNGLR_OPT_ACTIVATE:
		if (*len < sizeof(uint8_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_ACTIVATE "
			    "len too small %lu", *len);
			error = EINVAL;
			goto done;
		}

		if (data != NULL) {
			*(uint8_t *)data = p_pkt_mnglr->activate;
		}
		break;
	default:
		error = ENOPROTOOPT;
		break;
	}
done:
	pkt_mnglr_rw_unlock_shared(&pkt_mnglr_lck_rw);

	return error;
}

static errno_t
pkt_mnglr_ctl_setopt(kern_ctl_ref kctlref, u_int32_t kcunit, void *unitinfo,
    int opt, void *data, size_t len)
{
#pragma unused(kctlref, opt)
	errno_t error = 0;
	struct packet_mangler *p_pkt_mnglr = (struct packet_mangler *)unitinfo;

	PKT_MNGLR_LOG(LOG_NOTICE, "");

	pkt_mnglr_rw_lock_exclusive(&pkt_mnglr_lck_rw);

	if (packet_manglers == NULL) {
		PKT_MNGLR_LOG(LOG_ERR, "no packet filter");
		error = EINVAL;
		goto done;
	}
	if (kcunit > MAX_PACKET_MANGLER) {
		PKT_MNGLR_LOG(LOG_ERR, "kcunit %u > MAX_PACKET_MANGLER (%d)",
		    kcunit, MAX_PACKET_MANGLER);
		error = EINVAL;
		goto done;
	}
	if (p_pkt_mnglr != (void *)packet_manglers[kcunit - 1]) {
		PKT_MNGLR_LOG(LOG_ERR, "unitinfo does not match for kcunit %u",
		    kcunit);
		error = EINVAL;
		goto done;
	}
	switch (opt) {
	case PKT_MNGLR_OPT_PROTO_ACT_MASK:
		if (len < sizeof(uint32_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_PROTO_ACT_MASK "
			    "len too small %lu", len);
			error = EINVAL;
			goto done;
		}
		if (p_pkt_mnglr->proto_action_mask != 0) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_PROTO_ACT_MASK "
			    "already set %u",
			    p_pkt_mnglr->proto_action_mask);
			error = EINVAL;
			goto done;
		}
		p_pkt_mnglr->proto_action_mask = *(uint32_t *)data;
		PKT_MNGLR_LOG(LOG_INFO, "p_pkt_mnglr->proto_action_mask set to :%d", p_pkt_mnglr->proto_action_mask);
		break;
	case PKT_MNGLR_OPT_IP_ACT_MASK:
		if (len < sizeof(uint32_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_IP_ACT_MASK "
			    "len too small %lu", len);
			error = EINVAL;
			goto done;
		}
		if (p_pkt_mnglr->ip_action_mask != 0) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_IP_ACT_MASK "
			    "already set %u",
			    p_pkt_mnglr->ip_action_mask);
			error = EINVAL;
			goto done;
		}
		p_pkt_mnglr->ip_action_mask = *(uint32_t *)data;
		break;
	case PKT_MNGLR_OPT_LOCAL_IP:
		if (len < sizeof(struct sockaddr_storage)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_LOCAL_IP "
			    "len too small %lu", len);
			error = EINVAL;
			goto done;
		}
		if (p_pkt_mnglr->lsaddr.ss_family) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_LOCAL_IP "
			    "already set");
			error = EINVAL;
			goto done;
		}
		p_pkt_mnglr->lsaddr = *(struct sockaddr_storage *)data;
		break;
	case PKT_MNGLR_OPT_REMOTE_IP:
		if (len < sizeof(struct sockaddr_storage)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_REMOTE_IP "
			    "len too small %lu", len);
			error = EINVAL;
			goto done;
		}
		if (p_pkt_mnglr->rsaddr.ss_family) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_REMOTE_IP "
			    "already set");
			error = EINVAL;
			goto done;
		}

		p_pkt_mnglr->rsaddr = *(struct sockaddr_storage *)data;
		PKT_MNGLR_LOG(LOG_INFO,
		    "Remote IP registered for address family: %d",
		    p_pkt_mnglr->rsaddr.ss_family);
		break;
	case PKT_MNGLR_OPT_LOCAL_PORT:
		if (len < sizeof(uint16_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_LOCAL_PORT "
			    "len too small %lu", len);
			error = EINVAL;
			goto done;
		}
		if (p_pkt_mnglr->lport != 0) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_LOCAL_PORT "
			    "already set %d",
			    p_pkt_mnglr->lport);
			error = EINVAL;
			goto done;
		}
		p_pkt_mnglr->lport = *(uint16_t *)data;
		break;
	case PKT_MNGLR_OPT_REMOTE_PORT:
		if (len < sizeof(uint16_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_REMOTE_PORT "
			    "len too small %lu", len);
			error = EINVAL;
			goto done;
		}
		if (p_pkt_mnglr->rport != 0) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_REMOTE_PORT "
			    "already set %d",
			    p_pkt_mnglr->rport);
			error = EINVAL;
			goto done;
		}
		p_pkt_mnglr->rport = *(uint16_t *)data;
		break;
	case PKT_MNGLR_OPT_DIRECTION:
		if (len < sizeof(uint32_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_DIRECTION "
			    "len too small %lu", len);
			error = EINVAL;
			goto done;
		}
		if (p_pkt_mnglr->dir != 0) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_DIRECTION "
			    "already set %u",
			    p_pkt_mnglr->dir);
			error = EINVAL;
			goto done;
		}
		p_pkt_mnglr->dir = *(uint32_t *)data;
		break;
	case PKT_MNGLR_OPT_PROTOCOL:
		if (len < sizeof(uint32_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_PROTOCOL "
			    "len too small %lu", len);
			error = EINVAL;
			goto done;
		}
		if (p_pkt_mnglr->proto != 0) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_PROTOCOL "
			    "already set %u",
			    p_pkt_mnglr->proto);
			error = EINVAL;
			goto done;
		}
		p_pkt_mnglr->proto = *(uint32_t *)data;
		break;
	case PKT_MNGLR_OPT_ACTIVATE:
		if (len < sizeof(uint8_t)) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_ACTIVATE "
			    "len too small %lu", len);
			error = EINVAL;
			goto done;
		}
		if (p_pkt_mnglr->activate != 0) {
			PKT_MNGLR_LOG(LOG_ERR, "PKT_MNGLR_OPT_ACTIVATE "
			    "already set %u",
			    p_pkt_mnglr->activate);
			error = EINVAL;
			goto done;
		}
		p_pkt_mnglr->activate = *(uint8_t *)data;
		PKT_MNGLR_LOG(LOG_ERR, "p_pkt_mnglr->activate set to :%d",
		    p_pkt_mnglr->activate);
		break;
	default:
		error = ENOPROTOOPT;
		break;
	}
done:
	pkt_mnglr_rw_unlock_exclusive(&pkt_mnglr_lck_rw);

	return error;
}

void
pkt_mnglr_init(void)
{
	struct kern_ctl_reg kern_ctl;
	errno_t error = 0;
	vm_size_t pkt_mnglr_size = 0;

	PKT_MNGLR_LOG(LOG_NOTICE, "");

	/*
	 * Compile time verifications
	 */
	_CASSERT(PKT_MNGLR_MAX_FILTER_COUNT == MAX_PACKET_MANGLER);

	/*
	 * Zone for packet mangler kernel control sockets
	 */
	pkt_mnglr_size = sizeof(struct packet_mangler);
	packet_mangler_zone = zinit(pkt_mnglr_size,
	    PACKET_MANGLER_ZONE_MAX * pkt_mnglr_size,
	    0,
	    PACKET_MANGLER_ZONE_NAME);

	if (packet_mangler_zone == NULL) {
		panic("%s: zinit(%s) failed", __func__,
		    PACKET_MANGLER_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(packet_mangler_zone, Z_CALLERACCT, FALSE);
	zone_change(packet_mangler_zone, Z_EXPAND, TRUE);

	/*
	 * Allocate locks
	 */
	pkt_mnglr_lck_grp_attr = lck_grp_attr_alloc_init();
	if (pkt_mnglr_lck_grp_attr == NULL) {
		panic("%s: lck_grp_attr_alloc_init failed", __func__);
		/* NOTREACHED */
	}
	pkt_mnglr_lck_grp = lck_grp_alloc_init("packet manglerr",
	    pkt_mnglr_lck_grp_attr);
	if (pkt_mnglr_lck_grp == NULL) {
		panic("%s: lck_grp_alloc_init failed", __func__);
		/* NOTREACHED */
	}
	pkt_mnglr_lck_attr = lck_attr_alloc_init();
	if (pkt_mnglr_lck_attr == NULL) {
		panic("%s: lck_attr_alloc_init failed", __func__);
		/* NOTREACHED */
	}
	lck_rw_init(&pkt_mnglr_lck_rw, pkt_mnglr_lck_grp, pkt_mnglr_lck_attr);

	/*
	 * Register kernel control
	 */
	bzero(&kern_ctl, sizeof(kern_ctl));
	strlcpy(kern_ctl.ctl_name, PACKET_MANGLER_CONTROL_NAME,
	    sizeof(kern_ctl.ctl_name));
	kern_ctl.ctl_flags = CTL_FLAG_PRIVILEGED | CTL_FLAG_REG_EXTENDED;
	kern_ctl.ctl_connect = pkt_mnglr_ctl_connect;
	kern_ctl.ctl_disconnect = pkt_mnglr_ctl_disconnect;
	kern_ctl.ctl_getopt = pkt_mnglr_ctl_getopt;
	kern_ctl.ctl_setopt = pkt_mnglr_ctl_setopt;
	error = ctl_register(&kern_ctl, &pkt_mnglr_kctlref);
	if (error != 0) {
		PKT_MNGLR_LOG(LOG_ERR, "ctl_register failed: %d", error);
	} else {
		PKT_MNGLR_LOG(LOG_INFO, "Registered packet mangler kernel control.");
	}
}

static errno_t
pktmnglr_ipfilter_output(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
	struct packet_mangler *p_pkt_mnglr = (struct packet_mangler *)cookie;
	struct ip ip;
	struct tcphdr tcp;
	int optlen = 0;
	errno_t error = 0;

#pragma unused(tcp, optlen, options)
	if (p_pkt_mnglr == NULL) {
		goto output_done;
	}

	if (!p_pkt_mnglr->activate) {
		goto output_done;
	}

	if (p_pkt_mnglr->dir == IN) {
		goto output_done;
	}

	if (data == NULL) {
		PKT_MNGLR_LOG(LOG_ERR, "Data pointer is NULL");
		goto output_done;
	}

	/* Check for IP filter options */
	error = mbuf_copydata(*data, 0, sizeof(ip), &ip);
	if (error) {
		PKT_MNGLR_LOG(LOG_ERR, "Could not make local IP header copy");
		goto output_done;
	}

	if ((p_pkt_mnglr->lsaddr.ss_family == AF_INET6) && (ip.ip_v == 4)) {
		goto output_done;
	}

	if ((p_pkt_mnglr->lsaddr.ss_family == AF_INET) && (ip.ip_v == 6)) {
		goto output_done;
	}

	if (p_pkt_mnglr->lsaddr.ss_family == AF_INET) {
		struct sockaddr_in laddr = *(struct sockaddr_in *)(&(p_pkt_mnglr->lsaddr));
		if (ip.ip_src.s_addr != laddr.sin_addr.s_addr) {
			goto output_done;
		}
	}

	if (p_pkt_mnglr->rsaddr.ss_family == AF_INET) {
		struct sockaddr_in raddr = *(struct sockaddr_in *)(&(p_pkt_mnglr->rsaddr));
		if (ip.ip_dst.s_addr != raddr.sin_addr.s_addr) {
			goto output_done;
		}
	}

	if (ip.ip_v != 4) {
		PKT_MNGLR_LOG(LOG_INFO,
		    "%s:%d Not handling IP version %d\n",
		    __func__, __LINE__, ip.ip_v);
		goto output_done;
	}

output_done:
	/* Not handling output flow */
	return 0;
}

#define TCP_MAX_OPTLEN  40

static errno_t
pktmnglr_ipfilter_input(void *cookie, mbuf_t *data, int offset, u_int8_t protocol)
{
	struct packet_mangler *p_pkt_mnglr = (struct packet_mangler *)cookie;
	struct ip ip;
	struct tcphdr tcp;
	int ip_pld_len;
	errno_t error = 0;

	if (p_pkt_mnglr == NULL) {
		PKT_MNGLR_LOG(LOG_ERR, "p_pkt_mnglr is NULL");
		goto input_done;
	}

	if (p_pkt_mnglr->activate == 0) {
		PKT_MNGLR_LOG(LOG_INFO, "p_pkt_mnglr not yet activated");
		goto input_done;
	}

	if (p_pkt_mnglr->dir == OUT) {
		goto input_done;
	}

	if (data == NULL) {
		PKT_MNGLR_LOG(LOG_ERR, "Data pointer is NULL");
		goto input_done;
	}

	/* Check for IP filter options */
	error = mbuf_copydata(*data, 0, sizeof(ip), &ip);
	if (error) {
		PKT_MNGLR_LOG(LOG_ERR, "Could not make local IP header copy");
		goto input_done;
	}

	if ((p_pkt_mnglr->lsaddr.ss_family == AF_INET6) && (ip.ip_v == 4)) {
		PKT_MNGLR_LOG(LOG_INFO, "Skipping filtering as address family of packet is IPv4 but local "
		    "address is set to IPv6");
		goto input_done;
	}

	if ((p_pkt_mnglr->lsaddr.ss_family == AF_INET) && (ip.ip_v == 6)) {
		PKT_MNGLR_LOG(LOG_INFO, "Skipping filtering as address family "
		    "of packet is IPv6 but local address is set to IPv4");
		goto input_done;
	}

	if (p_pkt_mnglr->lsaddr.ss_family == AF_INET) {
		struct sockaddr_in laddr = *(struct sockaddr_in *)(&(p_pkt_mnglr->lsaddr));
		if (ip.ip_dst.s_addr != laddr.sin_addr.s_addr) {
			goto input_done;
		}
	}

	if (p_pkt_mnglr->rsaddr.ss_family == AF_INET) {
		struct sockaddr_in raddr = *(struct sockaddr_in *)(&(p_pkt_mnglr->rsaddr));
		if (ip.ip_src.s_addr != raddr.sin_addr.s_addr) {
			goto input_done;
		}
		PKT_MNGLR_LOG(LOG_INFO, "Remote IP: %x Source IP: %x in input path",
		    raddr.sin_addr.s_addr,
		    ip.ip_src.s_addr);
	}

	if (ip.ip_v != 4) {
		goto input_done;
	}

	ip_pld_len = ntohs(ip.ip_len) - (ip.ip_hl << 2);

	if (protocol != p_pkt_mnglr->proto) {
		PKT_MNGLR_LOG(LOG_INFO, "Skip: Protocol mismatch");
		goto input_done;
	}

	switch (protocol) {
	case IPPROTO_TCP:
		if (ip_pld_len < (int) sizeof(tcp)) {
			PKT_MNGLR_LOG(LOG_ERR, "IP total len not big enough for TCP: %d", ip_pld_len);
			goto drop_it;
		}

		error = mbuf_copydata(*data, offset, sizeof(tcp), &tcp);
		if (error) {
			PKT_MNGLR_LOG(LOG_ERR, "Could not make local TCP header copy");
			goto input_done;
		}

		if (p_pkt_mnglr->lport && (p_pkt_mnglr->lport != tcp.th_dport)) {
			PKT_MNGLR_LOG(LOG_INFO, "Local port and IP des port do not match");
			goto input_done;
		}

		if (p_pkt_mnglr->rport && (p_pkt_mnglr->rport != tcp.th_sport)) {
			PKT_MNGLR_LOG(LOG_INFO, "Remote port and IP src port do not match");
			goto input_done;
		}
		break;
	case IPPROTO_UDP:
		goto input_done;
	case IPPROTO_ICMP:
		goto input_done;
	case IPPROTO_ICMPV6:
		goto input_done;
	default:
		goto input_done;
	}

	/* XXX Do IP actions here */
	PKT_MNGLR_LOG(LOG_INFO, "Proceeding with packet mangler actions on the packet");

	/* Protocol actions */
	switch (protocol) {
	case IPPROTO_TCP:
		if (p_pkt_mnglr->proto_action_mask) {
			char tcp_opt_buf[TCP_MAX_OPTLEN] = {0};
			int orig_tcp_optlen;
			int tcp_optlen = 0;
			int i = 0, off;

			off = (tcp.th_off << 2);

			if (off < (int) sizeof(struct tcphdr) || off > ip_pld_len) {
				PKT_MNGLR_LOG(LOG_ERR, "TCP header offset is wrong: %d", off);
				goto drop_it;
			}


			tcp_optlen = off - sizeof(struct tcphdr);

			PKT_MNGLR_LOG(LOG_INFO, "Packet from F5 is TCP\n");
			PKT_MNGLR_LOG(LOG_INFO, "Optlen: %d\n", tcp_optlen);
			orig_tcp_optlen = tcp_optlen;
			if (orig_tcp_optlen) {
				error = mbuf_copydata(*data, offset + sizeof(struct tcphdr), orig_tcp_optlen, tcp_opt_buf);
				if (error) {
					PKT_MNGLR_LOG(LOG_ERR, "Failed to copy tcp options: error %d offset %d optlen %d", error, offset, orig_tcp_optlen);
					goto input_done;
				}
			}

			while (tcp_optlen > 0) {
				if (tcp_opt_buf[i] == 0x1) {
					PKT_MNGLR_LOG(LOG_INFO, "Skipping NOP\n");
					tcp_optlen--;
					i++;
					continue;
				} else if ((tcp_opt_buf[i] != 0) && (tcp_opt_buf[i] != TCP_OPT_MULTIPATH_TCP)) {
					PKT_MNGLR_LOG(LOG_INFO, "Skipping option %x\n", tcp_opt_buf[i]);

					/* Minimum TCP option size is 2 */
					if (tcp_opt_buf[i + 1] < 2) {
						PKT_MNGLR_LOG(LOG_ERR, "Received suspicious TCP option");
						goto drop_it;
					}
					tcp_optlen -= tcp_opt_buf[i + 1];
					i += tcp_opt_buf[i + 1];
					continue;
				} else if (tcp_opt_buf[i] == TCP_OPT_MULTIPATH_TCP) {
					int j = 0;
					unsigned char mptcpoptlen = tcp_opt_buf[i + 1];
					uint8_t sbtver = tcp_opt_buf[i + MPTCP_SBT_VER_OFFSET];
					uint8_t subtype = sbtver >> 4;

					PKT_MNGLR_LOG(LOG_INFO, "Got MPTCP option %x\n", tcp_opt_buf[i]);
					PKT_MNGLR_LOG(LOG_INFO, "Got MPTCP subtype %x\n", subtype);
					if (subtype == MPTCP_SUBTYPE_DSS) {
						PKT_MNGLR_LOG(LOG_INFO, "Got DSS option\n");
						PKT_MNGLR_LOG(LOG_INFO, "Protocol option mask: %d\n", p_pkt_mnglr->proto_action_mask);
						if (p_pkt_mnglr->proto_action_mask &
						    PKT_MNGLR_TCP_ACT_DSS_DROP) {
							goto drop_it;
						}
					}

					PKT_MNGLR_LOG(LOG_INFO, "Got MPTCP option %x\n", tcp_opt_buf[i]);
					for (; j < mptcpoptlen && j < tcp_optlen; j++) {
						if (p_pkt_mnglr->proto_action_mask &
						    PKT_MNGLR_TCP_ACT_NOP_MPTCP) {
							tcp_opt_buf[i + j] = 0x1;
						}
					}
					tcp_optlen -= mptcpoptlen;
					i += mptcpoptlen;
				} else {
					tcp_optlen--;
					i++;
				}
			}

			if (orig_tcp_optlen) {
				error = mbuf_copyback(*data,
				    offset + sizeof(struct tcphdr),
				    orig_tcp_optlen, tcp_opt_buf, MBUF_WAITOK);

				if (error) {
					PKT_MNGLR_LOG(LOG_ERR,
					    "Failed to copy tcp options back: error %d offset %d optlen %d",
					    error, offset, orig_tcp_optlen);
					goto input_done;
				}
			}
		}
		break;
	case IPPROTO_UDP:
		/* Don't handle UDP */
		break;
	case IPPROTO_ICMP:
		break;
	case IPPROTO_ICMPV6:
		break;
	default:
		break;
	}
	chksm_update(*data);
input_done:
	return 0;

drop_it:
	PKT_MNGLR_LOG(LOG_INFO, "Dropping packet\n");
	mbuf_freem(*data);
	return EJUSTRETURN;
}

static void
pktmnglr_ipfilter_detach(void *cookie)
{
#pragma unused(cookie)
	return;
}

/* XXX Still need to modify this to use mbuf_copy* macros */
static void
chksm_update(mbuf_t data)
{
	u_int16_t ip_sum;
	u_int16_t tsum;
	struct tcphdr *tcp;
	errno_t err;

	unsigned char *ptr = (unsigned char *)mbuf_data(data);
	struct ip *ip = (struct ip *)(void *)ptr;
	if (ip->ip_v != 4) {
		return;
	}

	ip->ip_sum = 0;
	err = mbuf_inet_cksum(data, 0, 0, ip->ip_hl << 2, &ip_sum); // ip sum
	if (err == 0) {
		ip->ip_sum = ip_sum;
	}
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		tcp = (struct tcphdr *)(void *)(ptr + (ip->ip_hl << 2));
		tcp->th_sum = 0;
		err = mbuf_inet_cksum(data, IPPROTO_TCP, ip->ip_hl << 2,
		        ntohs(ip->ip_len) - (ip->ip_hl << 2), &tsum);
		if (err == 0) {
			tcp->th_sum = tsum;
		}
		break;
	case IPPROTO_UDP:
		/* Don't handle UDP */
		break;
	case IPPROTO_ICMP:
		break;
	case IPPROTO_ICMPV6:
		break;
	default:
		break;
	}

	mbuf_clear_csum_performed(data);
	return;
}
