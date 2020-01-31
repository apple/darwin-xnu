/*
 * Copyright (c) 2017-2018 Apple Inc. All rights reserved.
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

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/mcache.h>
#include <sys/malloc.h>
#include <sys/kauth.h>
#include <sys/bitstring.h>
#include <sys/priv.h>
#include <sys/protosw.h>
#include <sys/socket.h>

#include <kern/locks.h>
#include <kern/zalloc.h>

#include <libkern/libkern.h>

#include <net/kpi_interface.h>
#include <net/if_var.h>
#include <net/if_ports_used.h>

#include <netinet/in_pcb.h>


#include <stdbool.h>

#include <os/log.h>

extern bool IOPMCopySleepWakeUUIDKey(char *buffer, size_t buf_len);

SYSCTL_DECL(_net_link_generic_system);

SYSCTL_NODE(_net_link_generic_system, OID_AUTO, port_used,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "if port used");

static uuid_t           current_wakeuuid;
SYSCTL_OPAQUE(_net_link_generic_system_port_used, OID_AUTO, current_wakeuuid,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    current_wakeuuid, sizeof(uuid_t), "S,uuid_t", "");

static int sysctl_net_port_info_list SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, list,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
    sysctl_net_port_info_list, "S,xnpigen", "");

static int use_test_wakeuuid = 0;
static uuid_t test_wakeuuid;
static uuid_string_t test_wakeuuid_str;

#if (DEVELOPMENT || DEBUG)
SYSCTL_INT(_net_link_generic_system_port_used, OID_AUTO, use_test_wakeuuid,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &use_test_wakeuuid, 0, "");

int sysctl_new_test_wakeuuid SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, new_test_wakeuuid,
    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    sysctl_new_test_wakeuuid, "S,uuid_t", "");

int sysctl_clear_test_wakeuuid SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, clear_test_wakeuuid,
    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    sysctl_clear_test_wakeuuid, "S,uuid_t", "");

int sysctl_test_wakeuuid_str SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, test_wakeuuid_str,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    sysctl_test_wakeuuid_str, "A", "");

SYSCTL_OPAQUE(_net_link_generic_system_port_used, OID_AUTO, test_wakeuuid,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    test_wakeuuid, sizeof(uuid_t), "S,uuid_t", "");
#endif /* (DEVELOPMENT || DEBUG) */

static int sysctl_get_ports_used SYSCTL_HANDLER_ARGS;
SYSCTL_NODE(_net_link_generic_system, OID_AUTO, get_ports_used,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    sysctl_get_ports_used, "");

static uint32_t net_port_entry_count = 0;
SYSCTL_UINT(_net_link_generic_system_port_used, OID_AUTO, entry_count,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &net_port_entry_count, 0, "");

static uint32_t net_port_entry_gen = 0;
SYSCTL_UINT(_net_link_generic_system_port_used, OID_AUTO, entry_gen,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &net_port_entry_gen, 0, "");

static int if_ports_used_verbose = 0;
SYSCTL_INT(_net_link_generic_system_port_used, OID_AUTO, verbose,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_ports_used_verbose, 0, "");

static unsigned long wakeuuid_not_set_count = 0;
SYSCTL_ULONG(_net_link_generic_system_port_used, OID_AUTO,
    wakeuuid_not_set_count, CTLFLAG_RD | CTLFLAG_LOCKED,
    &wakeuuid_not_set_count, 0);

struct timeval wakeuuid_not_set_last_time;
int sysctl_wakeuuid_not_set_last_time SYSCTL_HANDLER_ARGS;
static SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO,
    wakeuuid_not_set_last_time, CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_wakeuuid_not_set_last_time, "S,timeval", "");

char wakeuuid_not_set_last_if[IFXNAMSIZ];
int sysctl_wakeuuid_not_set_last_if SYSCTL_HANDLER_ARGS;
static SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO,
    wakeuuid_not_set_last_if, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_wakeuuid_not_set_last_if, "A", "");


static int if_ports_used_inited = 0;

decl_lck_mtx_data(static, net_port_entry_head_lock);
static lck_grp_t *net_port_entry_head_lock_group;

struct net_port_entry {
	SLIST_ENTRY(net_port_entry)     npe_next;
	struct net_port_info            npe_npi;
};

static struct zone *net_port_entry_zone = NULL;

#define NET_PORT_ENTRY_ZONE_MAX 128
#define NET_PORT_ENTRY_ZONE_NAME "net_port_entry"

static SLIST_HEAD(net_port_entry_list, net_port_entry) net_port_entry_list =
    SLIST_HEAD_INITIALIZER(&net_port_entry_list);

struct timeval wakeuiid_last_check;

void
if_ports_used_init(void)
{
	if (if_ports_used_inited == 0) {
		lck_grp_attr_t *lck_grp_attributes = NULL;
		lck_attr_t *lck_attributes = NULL;

		timerclear(&wakeuiid_last_check);
		uuid_clear(current_wakeuuid);
		uuid_clear(test_wakeuuid);

		lck_grp_attributes = lck_grp_attr_alloc_init();
		net_port_entry_head_lock_group = lck_grp_alloc_init(
			"net port entry lock", lck_grp_attributes);

		lck_attributes = lck_attr_alloc_init();
		if (lck_attributes == NULL) {
			panic("%s: lck_attr_alloc_init() failed", __func__);
		}
		lck_mtx_init(&net_port_entry_head_lock,
		    net_port_entry_head_lock_group,
		    lck_attributes);

		net_port_entry_count = 0;
		net_port_entry_zone = zinit(sizeof(struct net_port_entry),
		    NET_PORT_ENTRY_ZONE_MAX * sizeof(struct net_port_entry),
		    0, NET_PORT_ENTRY_ZONE_NAME);
		if (net_port_entry_zone == NULL) {
			panic("%s: zinit(%s) failed", __func__,
			    NET_PORT_ENTRY_ZONE_NAME);
		}
		zone_change(net_port_entry_zone, Z_EXPAND, TRUE);
		zone_change(net_port_entry_zone, Z_CALLERACCT, FALSE);

		if_ports_used_inited = 1;

		lck_attr_free(lck_attributes);
		lck_grp_attr_free(lck_grp_attributes);
	}
}

static void
net_port_entry_list_clear(void)
{
	struct net_port_entry *npe;

	LCK_MTX_ASSERT(&net_port_entry_head_lock, LCK_MTX_ASSERT_OWNED);

	while ((npe = SLIST_FIRST(&net_port_entry_list)) != NULL) {
		SLIST_REMOVE_HEAD(&net_port_entry_list, npe_next);

		zfree(net_port_entry_zone, npe);
	}
	net_port_entry_count = 0;
	net_port_entry_gen++;
}

static bool
get_test_wake_uuid(uuid_string_t wakeuuid_str, size_t len)
{
	if (__improbable(use_test_wakeuuid)) {
		if (!uuid_is_null(test_wakeuuid)) {
			if (wakeuuid_str != NULL && len != 0) {
				uuid_unparse(test_wakeuuid, wakeuuid_str);
			}
			return true;
		} else if (strlen(test_wakeuuid_str) != 0) {
			if (wakeuuid_str != NULL && len != 0) {
				strlcpy(wakeuuid_str, test_wakeuuid_str, len);
			}
			return true;
		} else {
			return false;
		}
	} else {
		return false;
	}
}

static bool
is_wakeuuid_set(void)
{
	/*
	 * IOPMCopySleepWakeUUIDKey() tells if SleepWakeUUID is currently set
	 * That means we are currently in a sleep/wake cycle
	 */
	return get_test_wake_uuid(NULL, 0) || IOPMCopySleepWakeUUIDKey(NULL, 0);
}

void
if_ports_used_update_wakeuuid(struct ifnet *ifp)
{
	uuid_t wakeuuid;
	bool wakeuuid_is_set = false;
	bool updated = false;
	uuid_string_t wakeuuid_str;

	uuid_clear(wakeuuid);

	if (__improbable(use_test_wakeuuid)) {
		wakeuuid_is_set = get_test_wake_uuid(wakeuuid_str,
		    sizeof(wakeuuid_str));
	} else {
		wakeuuid_is_set = IOPMCopySleepWakeUUIDKey(wakeuuid_str,
		    sizeof(wakeuuid_str));
	}

	if (wakeuuid_is_set) {
		if (uuid_parse(wakeuuid_str, wakeuuid) != 0) {
			os_log(OS_LOG_DEFAULT,
			    "%s: IOPMCopySleepWakeUUIDKey got bad value %s\n",
			    __func__, wakeuuid_str);
			wakeuuid_is_set = false;
		}
	}

	if (!wakeuuid_is_set) {
		if (if_ports_used_verbose > 0) {
			os_log_info(OS_LOG_DEFAULT,
			    "%s: SleepWakeUUID not set, "
			    "don't update the port list for %s\n",
			    __func__, ifp != NULL ? if_name(ifp) : "");
		}
		wakeuuid_not_set_count += 1;
		if (ifp != NULL) {
			microtime(&wakeuuid_not_set_last_time);
			strlcpy(wakeuuid_not_set_last_if, if_name(ifp),
			    sizeof(wakeuuid_not_set_last_if));
		}
		return;
	}

	lck_mtx_lock(&net_port_entry_head_lock);
	if (uuid_compare(wakeuuid, current_wakeuuid) != 0) {
		net_port_entry_list_clear();
		uuid_copy(current_wakeuuid, wakeuuid);
		updated = true;
	}
	/*
	 * Record the time last checked
	 */
	microuptime(&wakeuiid_last_check);
	lck_mtx_unlock(&net_port_entry_head_lock);

	if (updated && if_ports_used_verbose > 0) {
		uuid_string_t uuid_str;

		uuid_unparse(current_wakeuuid, uuid_str);
		log(LOG_ERR, "%s: current wakeuuid %s\n",
		    __func__,
		    uuid_str);
	}
}

static bool
net_port_info_equal(const struct net_port_info *x,
    const struct net_port_info *y)
{
	ASSERT(x != NULL && y != NULL);

	if (x->npi_if_index == y->npi_if_index &&
	    x->npi_local_port == y->npi_local_port &&
	    x->npi_foreign_port == y->npi_foreign_port &&
	    x->npi_owner_pid == y->npi_owner_pid &&
	    x->npi_effective_pid == y->npi_effective_pid &&
	    x->npi_flags == y->npi_flags &&
	    memcmp(&x->npi_local_addr_, &y->npi_local_addr_,
	    sizeof(union in_addr_4_6)) == 0 &&
	    memcmp(&x->npi_foreign_addr_, &y->npi_foreign_addr_,
	    sizeof(union in_addr_4_6)) == 0) {
		return true;
	}
	return false;
}

static bool
net_port_info_has_entry(const struct net_port_info *npi)
{
	struct net_port_entry *npe;

	LCK_MTX_ASSERT(&net_port_entry_head_lock, LCK_MTX_ASSERT_OWNED);

	SLIST_FOREACH(npe, &net_port_entry_list, npe_next) {
		if (net_port_info_equal(&npe->npe_npi, npi)) {
			return true;
		}
	}

	return false;
}

static bool
net_port_info_add_entry(const struct net_port_info *npi)
{
	struct net_port_entry   *npe = NULL;
	uint32_t num = 0;
	bool entry_added = false;

	ASSERT(npi != NULL);

	if (__improbable(is_wakeuuid_set() == false)) {
		if (if_ports_used_verbose > 0) {
			log(LOG_ERR, "%s: wakeuuid not set %u not adding "
			    "port: %u flags: 0x%xif: %u pid: %u epid %u\n",
			    __func__,
			    ntohs(npi->npi_local_port),
			    npi->npi_flags,
			    npi->npi_if_index,
			    npi->npi_owner_pid,
			    npi->npi_effective_pid);
		}
		return 0;
	}

	npe = zalloc(net_port_entry_zone);
	if (__improbable(npe == NULL)) {
		log(LOG_ERR, "%s: zalloc() failed for "
		    "port: %u flags: 0x%x if: %u pid: %u epid %u\n",
		    __func__,
		    ntohs(npi->npi_local_port),
		    npi->npi_flags,
		    npi->npi_if_index,
		    npi->npi_owner_pid,
		    npi->npi_effective_pid);
		return 0;
	}
	bzero(npe, sizeof(struct net_port_entry));

	memcpy(&npe->npe_npi, npi, sizeof(npe->npe_npi));

	lck_mtx_lock(&net_port_entry_head_lock);

	if (net_port_info_has_entry(npi) == false) {
		SLIST_INSERT_HEAD(&net_port_entry_list, npe, npe_next);
		num = net_port_entry_count++;
		entry_added = true;

		if (if_ports_used_verbose > 0) {
			log(LOG_ERR, "%s: num %u for "
			    "port: %u flags: 0x%x if: %u pid: %u epid %u\n",
			    __func__,
			    num,
			    ntohs(npi->npi_local_port),
			    npi->npi_flags,
			    npi->npi_if_index,
			    npi->npi_owner_pid,
			    npi->npi_effective_pid);
		}
	} else {
		if (if_ports_used_verbose > 0) {
			log(LOG_ERR, "%s: entry already added "
			    "port: %u flags: 0x%x if: %u pid: %u epid %u\n",
			    __func__,
			    ntohs(npi->npi_local_port),
			    npi->npi_flags,
			    npi->npi_if_index,
			    npi->npi_owner_pid,
			    npi->npi_effective_pid);
		}
	}

	lck_mtx_unlock(&net_port_entry_head_lock);

	if (entry_added == false) {
		zfree(net_port_entry_zone, npe);
		npe = NULL;
	}
	return entry_added;
}

#if (DEVELOPMENT || DEBUG)
int
sysctl_new_test_wakeuuid SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;

	if (kauth_cred_issuser(kauth_cred_get()) == 0) {
		return EPERM;
	}
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(uuid_t);
		return 0;
	}
	if (req->newptr != USER_ADDR_NULL) {
		uuid_generate(test_wakeuuid);
	}
	error = SYSCTL_OUT(req, test_wakeuuid,
	    MIN(sizeof(uuid_t), req->oldlen));

	return error;
}

int
sysctl_clear_test_wakeuuid SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;

	if (kauth_cred_issuser(kauth_cred_get()) == 0) {
		return EPERM;
	}
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(uuid_t);
		return 0;
	}
	if (req->newptr != USER_ADDR_NULL) {
		uuid_clear(test_wakeuuid);
	}
	error = SYSCTL_OUT(req, test_wakeuuid,
	    MIN(sizeof(uuid_t), req->oldlen));

	return error;
}

int
sysctl_test_wakeuuid_str SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;
	int changed;

	if (kauth_cred_issuser(kauth_cred_get()) == 0) {
		return EPERM;
	}
	error = sysctl_io_string(req, test_wakeuuid_str, sizeof(test_wakeuuid_str), 1, &changed);
	if (changed) {
		os_log_info(OS_LOG_DEFAULT, "%s: test_wakeuuid_str %s",
		    __func__, test_wakeuuid_str);
	}

	return error;
}

#endif /* (DEVELOPMENT || DEBUG) */

int
sysctl_wakeuuid_not_set_last_time SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	if (proc_is64bit(req->p)) {
		struct user64_timeval tv = {};

		tv.tv_sec = wakeuuid_not_set_last_time.tv_sec;
		tv.tv_usec = wakeuuid_not_set_last_time.tv_usec;
		return SYSCTL_OUT(req, &tv, sizeof(tv));
	} else {
		struct user32_timeval tv = {};

		tv.tv_sec = wakeuuid_not_set_last_time.tv_sec;
		tv.tv_usec = wakeuuid_not_set_last_time.tv_usec;
		return SYSCTL_OUT(req, &tv, sizeof(tv));
	}
}

int
sysctl_wakeuuid_not_set_last_if SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	return SYSCTL_OUT(req, &wakeuuid_not_set_last_if,
    strlen(wakeuuid_not_set_last_if) + 1);
}

static int
sysctl_net_port_info_list SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;
	struct xnpigen xnpigen;
	struct net_port_entry *npe;

	if ((error = priv_check_cred(kauth_cred_get(),
	    PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0)) != 0) {
		return EPERM;
	}
	lck_mtx_lock(&net_port_entry_head_lock);

	if (req->oldptr == USER_ADDR_NULL) {
		/* Add a 25 % cushion */
		uint32_t cnt = net_port_entry_count;
		cnt += cnt >> 4;
		req->oldidx = sizeof(struct xnpigen) +
		    cnt * sizeof(struct net_port_info);
		goto done;
	}

	memset(&xnpigen, 0, sizeof(struct xnpigen));
	xnpigen.xng_len = sizeof(struct xnpigen);
	xnpigen.xng_gen = net_port_entry_gen;
	uuid_copy(xnpigen.xng_wakeuuid, current_wakeuuid);
	xnpigen.xng_npi_count = net_port_entry_count;
	xnpigen.xng_npi_size = sizeof(struct net_port_info);
	error = SYSCTL_OUT(req, &xnpigen, sizeof(xnpigen));
	if (error != 0) {
		printf("%s: SYSCTL_OUT(xnpigen) error %d\n",
		    __func__, error);
		goto done;
	}

	SLIST_FOREACH(npe, &net_port_entry_list, npe_next) {
		error = SYSCTL_OUT(req, &npe->npe_npi,
		    sizeof(struct net_port_info));
		if (error != 0) {
			printf("%s: SYSCTL_OUT(npi) error %d\n",
			    __func__, error);
			goto done;
		}
	}
done:
	lck_mtx_unlock(&net_port_entry_head_lock);

	return error;
}

/*
 * Mirror the arguments of ifnet_get_local_ports_extended()
 *  ifindex
 *  protocol
 *  flags
 */
static int
sysctl_get_ports_used SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp)
	int *name = (int *)arg1;
	int namelen = arg2;
	int error = 0;
	int idx;
	protocol_family_t protocol;
	u_int32_t flags;
	ifnet_t ifp = NULL;
	u_int8_t *bitfield = NULL;

	if (req->newptr != USER_ADDR_NULL) {
		error = EPERM;
		goto done;
	}
	/*
	 * 3 is the required number of parameters: ifindex, protocol and flags
	 */
	if (namelen != 3) {
		error = ENOENT;
		goto done;
	}

	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = bitstr_size(IP_PORTRANGE_SIZE);
		goto done;
	}
	if (req->oldlen < bitstr_size(IP_PORTRANGE_SIZE)) {
		error = ENOMEM;
		goto done;
	}

	idx = name[0];
	protocol = name[1];
	flags = name[2];

	ifnet_head_lock_shared();
	if (!IF_INDEX_IN_RANGE(idx)) {
		ifnet_head_done();
		error = ENOENT;
		goto done;
	}
	ifp = ifindex2ifnet[idx];
	ifnet_head_done();

	bitfield = _MALLOC(bitstr_size(IP_PORTRANGE_SIZE), M_TEMP,
	    M_WAITOK | M_ZERO);
	if (bitfield == NULL) {
		error = ENOMEM;
		goto done;
	}
	error = ifnet_get_local_ports_extended(ifp, protocol, flags, bitfield);
	if (error != 0) {
		printf("%s: ifnet_get_local_ports_extended() error %d\n",
		    __func__, error);
		goto done;
	}
	error = SYSCTL_OUT(req, bitfield, bitstr_size(IP_PORTRANGE_SIZE));
done:
	if (bitfield != NULL) {
		_FREE(bitfield, M_TEMP);
	}
	return error;
}

__private_extern__ void
if_ports_used_add_inpcb(const uint32_t ifindex, const struct inpcb *inp)
{
	struct net_port_info npi;
	struct socket *so = inp->inp_socket;

	bzero(&npi, sizeof(struct net_port_info));

	npi.npi_if_index = ifindex;

	npi.npi_flags |= NPIF_SOCKET;

	npi.npi_timestamp.tv_sec = wakeuiid_last_check.tv_sec;
	npi.npi_timestamp.tv_usec = wakeuiid_last_check.tv_usec;

	if (SOCK_PROTO(so) == IPPROTO_TCP) {
		npi.npi_flags |= NPIF_TCP;
	} else if (SOCK_PROTO(so) == IPPROTO_UDP) {
		npi.npi_flags |= NPIF_UDP;
	} else {
		panic("%s: unexpected protocol %u for inp %p\n", __func__,
		    SOCK_PROTO(inp->inp_socket), inp);
	}

	uuid_copy(npi.npi_flow_uuid, inp->necp_client_uuid);

	npi.npi_local_port = inp->inp_lport;
	npi.npi_foreign_port = inp->inp_fport;

	if (inp->inp_vflag & INP_IPV4) {
		npi.npi_flags |= NPIF_IPV4;
		npi.npi_local_addr_in = inp->inp_laddr;
		npi.npi_foreign_addr_in = inp->inp_faddr;
	} else {
		npi.npi_flags |= NPIF_IPV6;
		memcpy(&npi.npi_local_addr_in6,
		    &inp->in6p_laddr, sizeof(struct in6_addr));
		memcpy(&npi.npi_foreign_addr_in6,
		    &inp->in6p_faddr, sizeof(struct in6_addr));
	}

	npi.npi_owner_pid = so->last_pid;

	if (so->last_pid != 0) {
		proc_name(so->last_pid, npi.npi_owner_pname,
		    sizeof(npi.npi_owner_pname));
	}

	if (so->so_flags & SOF_DELEGATED) {
		npi.npi_flags |= NPIF_DELEGATED;
		npi.npi_effective_pid = so->e_pid;
		if (so->e_pid != 0) {
			proc_name(so->e_pid, npi.npi_effective_pname,
			    sizeof(npi.npi_effective_pname));
		}
	} else {
		npi.npi_effective_pid = so->last_pid;
		if (so->last_pid != 0) {
			strlcpy(npi.npi_effective_pname, npi.npi_owner_pname,
			    sizeof(npi.npi_effective_pname));
		}
	}

	(void) net_port_info_add_entry(&npi);
}

