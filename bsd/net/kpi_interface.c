/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#include "kpi_interface.h"

#include <sys/queue.h>
#include <sys/param.h>	/* for definition of NULL */
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/kern_event.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/kpi_mbuf.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/dlil.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <libkern/libkern.h>
#include <kern/locks.h>

#if IF_LASTCHANGEUPTIME
#define TOUCHLASTCHANGE(__if_lastchange) microuptime(__if_lastchange)
#else
#define TOUCHLASTCHANGE(__if_lastchange) microtime(__if_lastchange)
#endif

extern lck_spin_t *dlil_input_lock;

/*
	Temporary work around until we have real reference counting
	
	We keep the bits about calling dlil_if_release (which should be
	called recycle) transparent by calling it from our if_free function
	pointer. We have to keep the client's original detach function
	somewhere so we can call it.
 */
static void
ifnet_kpi_free(
	ifnet_t ifp)
{
	ifnet_detached_func	detach_func = ifp->if_kpi_storage;
	
	if (detach_func)
		detach_func(ifp);
	
	if (ifp->if_broadcast.length > sizeof(ifp->if_broadcast.u.buffer)) {
		FREE(ifp->if_broadcast.u.ptr, M_IFADDR);
		ifp->if_broadcast.u.ptr = NULL;
	}
	
	dlil_if_release(ifp);
}

errno_t
ifnet_allocate(
	const struct ifnet_init_params *init,
	ifnet_t *interface)
{
	int error;
	struct ifnet *ifp = NULL;
	
	if (init->family == 0)
		return EINVAL;
	if (init->name == NULL ||
		init->output == NULL)
		return EINVAL;
	if (strlen(init->name) >= IFNAMSIZ)
		return EINVAL;
	if ((init->type & 0xFFFFFF00) != 0 || init->type == 0)
		return EINVAL;
	
	error = dlil_if_acquire(init->family, init->uniqueid, init->uniqueid_len, &ifp);
	if (error == 0)
	{		
		strncpy(ifp->if_name, init->name, IFNAMSIZ);
		ifp->if_type = init->type;
		ifp->if_family = init->family;
		ifp->if_unit = init->unit;
		ifp->if_output = init->output;
		ifp->if_demux = init->demux;
		ifp->if_add_proto_u.kpi = init->add_proto;
		ifp->if_del_proto = init->del_proto;
		ifp->if_check_multi = init->check_multi;
		ifp->if_framer = init->framer;
		ifp->if_softc = init->softc;
		ifp->if_ioctl = init->ioctl;
		ifp->if_set_bpf_tap = init->set_bpf_tap;
		ifp->if_free = ifnet_kpi_free;
		ifp->if_event = init->event;
		ifp->if_kpi_storage = init->detach;
		ifp->if_eflags |= IFEF_USEKPI;
		
		if (init->broadcast_len && init->broadcast_addr) {
			if (init->broadcast_len > sizeof(ifp->if_broadcast.u.buffer)) {
				MALLOC(ifp->if_broadcast.u.ptr, u_char*, init->broadcast_len, M_IFADDR, M_NOWAIT);
				if (ifp->if_broadcast.u.ptr == NULL) {
					error = ENOMEM;
				}
				else {
					bcopy(init->broadcast_addr, ifp->if_broadcast.u.ptr, init->broadcast_len);
				}
			}
			else {
				bcopy(init->broadcast_addr, ifp->if_broadcast.u.buffer, init->broadcast_len);
			}
			ifp->if_broadcast.length = init->broadcast_len;
		}
		else {
			bzero(&ifp->if_broadcast, sizeof(ifp->if_broadcast));
		}
		
		if (error == 0) {
			*interface = ifp;
			ifnet_reference(ifp); // temporary - this should be done in dlil_if_acquire
		}
		else {
			dlil_if_release(ifp);
			*interface = 0;
		}
	}
	
	/*
	  Note: We should do something here to indicate that we haven't been
	  attached yet. By doing so, we can catch the case in ifnet_release
	  where the reference count reaches zero and call the recycle
	  function. If the interface is attached, the interface will be
	  recycled when the interface's if_free function is called. If the
	  interface is never attached, the if_free function will never be
	  called and the interface will never be recycled.
	*/
	
	return error;
}

errno_t
ifnet_reference(
	ifnet_t interface)
{
	if (interface == NULL) return EINVAL;
	ifp_reference(interface);
	return 0;
}

errno_t
ifnet_release(
	ifnet_t interface)
{
	if (interface == NULL) return EINVAL;
	ifp_release(interface);
	return 0;
}

errno_t
ifnet_attach(
	ifnet_t interface,
	const struct sockaddr_dl *ll_addr)
{
	if (interface == NULL) return EINVAL;
	if (ll_addr && interface->if_addrlen == 0) {
		interface->if_addrlen = ll_addr->sdl_alen;
	}
	else if (ll_addr && ll_addr->sdl_alen != interface->if_addrlen) {
		return EINVAL;
	}
	return dlil_if_attach_with_address(interface, ll_addr);
}

errno_t
ifnet_detach(
	ifnet_t interface)
{
	errno_t	error;
	
	if (interface == NULL) return EINVAL;
	
	error = dlil_if_detach(interface);
	if (error == DLIL_WAIT_FOR_FREE) error = 0; /* Client should always wait for detach */
	
	return error;
}

void*
ifnet_softc(
	ifnet_t interface)
{
	return interface == NULL ? NULL : interface->if_softc;
}

const char*
ifnet_name(
	ifnet_t interface)
{
	return interface == NULL ? NULL : interface->if_name;
}

ifnet_family_t
ifnet_family(
	ifnet_t interface)
{
	return interface == NULL ? 0 : interface->if_family;
}

u_int32_t
ifnet_unit(
	ifnet_t interface)
{
	return interface == NULL ? (u_int32_t)0xffffffff : (u_int32_t)interface->if_unit;
}

u_int32_t
ifnet_index(
	ifnet_t interface)
{
	return interface == NULL ? (u_int32_t)0xffffffff : interface->if_index;
}

errno_t
ifnet_set_flags(
	ifnet_t interface,
	u_int16_t new_flags,
	u_int16_t mask)
{
	int lock;
	
	if (interface == NULL) return EINVAL;
	lock = (interface->if_lock != 0);
	
	if (lock) ifnet_lock_exclusive(interface);
	
	/* If we are modifying the up/down state, call if_updown */
	if (lock && (mask & IFF_UP) != 0) {
		if_updown(interface, (new_flags & IFF_UP) == IFF_UP);
	}
	
	interface->if_flags = (new_flags & mask) | (interface->if_flags & ~mask);
	if (lock) ifnet_lock_done(interface);
	
	return 0;
}

u_int16_t
ifnet_flags(
	ifnet_t interface)
{
	return interface == NULL ? 0 : interface->if_flags;
}

errno_t
ifnet_set_eflags(
	ifnet_t interface,
	u_int32_t new_flags,
	u_int32_t mask)
{
	int lock;
	
	if (interface == NULL) return EINVAL;
	lock = (interface->if_lock != 0);
	
	if (lock) ifnet_lock_exclusive(interface);
	interface->if_eflags = (new_flags & mask) | (interface->if_eflags & ~mask);
	if (lock) ifnet_lock_done(interface);
	
	return 0;
}

u_int32_t
ifnet_eflags(
	ifnet_t interface)
{
	return interface == NULL ? 0 : interface->if_eflags;
}

static const ifnet_offload_t offload_mask = IFNET_CSUM_IP | IFNET_CSUM_TCP |
			IFNET_CSUM_UDP | IFNET_CSUM_FRAGMENT | IFNET_IP_FRAGMENT |
			IFNET_CSUM_SUM16 | IFNET_VLAN_TAGGING | IFNET_VLAN_MTU;

errno_t
ifnet_set_offload(
	ifnet_t interface,
	ifnet_offload_t offload)
{
	int lock;
	
	if (interface == NULL) return EINVAL;
	lock = (interface->if_lock != 0);
	
	if (lock) ifnet_lock_exclusive(interface);
	interface->if_hwassist = (offload & offload_mask);
	if (lock) ifnet_lock_done(interface);
	
	return 0;
}

ifnet_offload_t
ifnet_offload(
	ifnet_t interface)
{
	return interface == NULL ? 0 : (interface->if_hwassist & offload_mask);
}

/*
 * Should MIB data store a copy?
 */
errno_t
ifnet_set_link_mib_data(
	ifnet_t interface,
	void* mibData,
	u_int32_t mibLen)
{
	int lock;
	
	if (interface == NULL) return EINVAL;
	lock = (interface->if_lock != 0);
	
	if (lock) ifnet_lock_exclusive(interface);
	interface->if_linkmib = (void*)mibData;
	interface->if_linkmiblen = mibLen;
	if (lock) ifnet_lock_done(interface);
	return 0;
}

errno_t
ifnet_get_link_mib_data(
	ifnet_t interface,
	void *mibData,
	u_int32_t *mibLen)
{
	errno_t	result = 0;
	int lock;
	
	if (interface == NULL) return EINVAL;
	lock = (interface->if_lock != NULL);
	
	if (lock) ifnet_lock_shared(interface);
	if (*mibLen < interface->if_linkmiblen)
		result = EMSGSIZE;
	if (result == 0 && interface->if_linkmib == NULL)
		result = ENOTSUP;
	
	if (result == 0) {
		*mibLen = interface->if_linkmiblen;
		bcopy(interface->if_linkmib, mibData, *mibLen);
	}
	if (lock) ifnet_lock_done(interface);
	
	return result;
}

u_int32_t
ifnet_get_link_mib_data_length(
	ifnet_t interface)
{
	return interface == NULL ? 0 : interface->if_linkmiblen;
}

errno_t
ifnet_attach_protocol(
	ifnet_t interface,
	protocol_family_t protocol,
	const struct ifnet_attach_proto_param *proto_details)
{
	if (interface == NULL || protocol == 0 || proto_details == NULL)
		return EINVAL;
	return dlil_attach_protocol_kpi(interface, protocol, proto_details);
}

errno_t
ifnet_detach_protocol(
	ifnet_t interface,
	protocol_family_t protocol)
{
	if (interface == NULL || protocol == 0) return EINVAL;
	return dlil_detach_protocol(interface, protocol);
}

errno_t
ifnet_output(
	ifnet_t interface,
	protocol_family_t protocol_family,
	mbuf_t m,
	void *route,
	const struct sockaddr *dest)
{
	if (interface == NULL || protocol_family == 0 || m == NULL) {
		if (m)
			mbuf_freem_list(m);
		return EINVAL;
	}
	return dlil_output(interface, protocol_family, m, route, dest, 0);
}

errno_t
ifnet_output_raw(
	ifnet_t interface,
	protocol_family_t protocol_family,
	mbuf_t m)
{
	if (interface == NULL || protocol_family == 0 || m == NULL) {
		if (m)
			mbuf_freem_list(m);
		return EINVAL;
	}
	return dlil_output(interface, protocol_family, m, NULL, NULL, 1);
}

errno_t
ifnet_input(
	ifnet_t interface,
	mbuf_t first_packet,
	const struct ifnet_stat_increment_param *stats)
{
	mbuf_t	last_packet = first_packet;
	
	if (interface == NULL || first_packet == NULL) {
		if (first_packet)
			mbuf_freem_list(first_packet);
		return EINVAL;
	}
	
	while (mbuf_nextpkt(last_packet) != NULL)
		last_packet = mbuf_nextpkt(last_packet);
	return dlil_input_with_stats(interface, first_packet, last_packet, stats);
}

errno_t
ifnet_ioctl(
	ifnet_t interface,
	protocol_family_t	protocol_family,
	u_int32_t ioctl_code,
	void *ioctl_arg)
{
	if (interface == NULL || protocol_family == 0 || ioctl_code == 0)
		return EINVAL;
	return dlil_ioctl(protocol_family, interface,
					  ioctl_code, ioctl_arg);
}

errno_t
ifnet_event(
	ifnet_t interface,
	struct kern_event_msg* event_ptr)
{
	if (interface == NULL || event_ptr == NULL) return EINVAL;
	return dlil_event(interface, event_ptr);
}

errno_t
ifnet_set_mtu(
	ifnet_t interface,
	u_int32_t mtu)
{
	if (interface == NULL) return EINVAL;
	interface->if_data.ifi_mtu = mtu;
	return 0;
}

u_int32_t
ifnet_mtu(
	ifnet_t interface)
{
	u_int32_t retval;
	retval = interface == NULL ? 0 : interface->if_data.ifi_mtu;
	return retval;
}

u_char
ifnet_type(
	ifnet_t interface)
{
	u_char retval;
	
	retval = interface == NULL ? 0 : interface->if_data.ifi_type;
	return retval;
}

#if 0
errno_t
ifnet_set_typelen(
	ifnet_t interface,
	u_char typelen)
{
	int lock = (interface->if_lock != 0);
	if (lock) ifnet_lock_exclusive(interface);
	interface->if_data.ifi_typelen = typelen;
	if (lock) ifnet_lock_done(interface);
	return 0;
}

u_char
ifnet_typelen(
	ifnet_t interface)
{
	u_char retval;
	retval = interface == NULL ? 0 : interface->if_data.ifi_typelen;
	return retval;
}
#endif

errno_t
ifnet_set_addrlen(
	ifnet_t interface,
	u_char addrlen)
{
	if (interface == NULL) return EINVAL;
	interface->if_data.ifi_addrlen = addrlen;
	return 0;
}

u_char
ifnet_addrlen(
	ifnet_t interface)
{
	u_char retval;
	retval = interface == NULL ? 0 : interface->if_data.ifi_addrlen;
	return retval;
}

errno_t
ifnet_set_hdrlen(
	ifnet_t interface,
	u_char hdrlen)
{
	if (interface == NULL) return EINVAL;
	interface->if_data.ifi_hdrlen = hdrlen;
	return 0;
}

u_char
ifnet_hdrlen(
	ifnet_t interface)
{
	u_char retval;
	retval = interface == NULL ? 0 : interface->if_data.ifi_hdrlen;
	return retval;
}

errno_t
ifnet_set_metric(
	ifnet_t interface,
	u_int32_t metric)
{
	if (interface == NULL) return EINVAL;
	interface->if_data.ifi_metric = metric;
	return 0;
}

u_int32_t
ifnet_metric(
	ifnet_t interface)
{
	u_int32_t retval;
	retval = interface == NULL ? 0 : interface->if_data.ifi_metric;
	return retval;
}

errno_t
ifnet_set_baudrate(
	ifnet_t interface,
	u_int64_t baudrate)
{
	if (interface == NULL) return EINVAL;
	/* Pin baudrate to 32 bits until we can change the storage size */
	interface->if_data.ifi_baudrate = baudrate > 0xFFFFFFFF ? 0xFFFFFFFF : baudrate;
	return 0;
}

u_int64_t
ifnet_baudrate(
	ifnet_t interface)
{
	u_int64_t retval;
	retval = interface == NULL ? 0 : interface->if_data.ifi_baudrate;
	return retval;
}

errno_t
ifnet_stat_increment(
	ifnet_t interface,
	const struct ifnet_stat_increment_param *counts)
{
	if (interface == NULL) return EINVAL;
	
	lck_spin_lock(dlil_input_lock);

	interface->if_data.ifi_ipackets += counts->packets_in;
	interface->if_data.ifi_ibytes += counts->bytes_in;
	interface->if_data.ifi_ierrors += counts->errors_in;

	interface->if_data.ifi_opackets += counts->packets_out;
	interface->if_data.ifi_obytes += counts->bytes_out;
	interface->if_data.ifi_oerrors += counts->errors_out;

	interface->if_data.ifi_collisions += counts->collisions;
	interface->if_data.ifi_iqdrops += counts->dropped;
	
	/* Touch the last change time. */
	TOUCHLASTCHANGE(&interface->if_lastchange);

	lck_spin_unlock(dlil_input_lock);
	
	return 0;
}

errno_t
ifnet_stat_increment_in(
	ifnet_t interface,
	u_int32_t packets_in,
	u_int32_t bytes_in,
	u_int32_t errors_in)
{
	if (interface == NULL) return EINVAL;
	
	lck_spin_lock(dlil_input_lock);

	interface->if_data.ifi_ipackets += packets_in;
	interface->if_data.ifi_ibytes += bytes_in;
	interface->if_data.ifi_ierrors += errors_in;

	TOUCHLASTCHANGE(&interface->if_lastchange);

	lck_spin_unlock(dlil_input_lock);
	
	return 0;
}

errno_t
ifnet_stat_increment_out(
	ifnet_t interface,
	u_int32_t packets_out,
	u_int32_t bytes_out,
	u_int32_t errors_out)
{
	if (interface == NULL) return EINVAL;
	
	lck_spin_lock(dlil_input_lock);

	interface->if_data.ifi_opackets += packets_out;
	interface->if_data.ifi_obytes += bytes_out;
	interface->if_data.ifi_oerrors += errors_out;

	TOUCHLASTCHANGE(&interface->if_lastchange);

	lck_spin_unlock(dlil_input_lock);
	
	return 0;
}

errno_t
ifnet_set_stat(
	ifnet_t interface,
	const struct ifnet_stats_param *stats)
{
	if (interface == NULL) return EINVAL;
	
	lck_spin_lock(dlil_input_lock);

	interface->if_data.ifi_ipackets = stats->packets_in;
	interface->if_data.ifi_ibytes = stats->bytes_in;
	interface->if_data.ifi_imcasts = stats->multicasts_in;
	interface->if_data.ifi_ierrors = stats->errors_in;
	
	interface->if_data.ifi_opackets = stats->packets_out;
	interface->if_data.ifi_obytes = stats->bytes_out;
	interface->if_data.ifi_omcasts = stats->multicasts_out;
	interface->if_data.ifi_oerrors = stats->errors_out;
	
	interface->if_data.ifi_collisions = stats->collisions;
	interface->if_data.ifi_iqdrops = stats->dropped;
	interface->if_data.ifi_noproto = stats->no_protocol;

	/* Touch the last change time. */
	TOUCHLASTCHANGE(&interface->if_lastchange);

	lck_spin_unlock(dlil_input_lock);
	
	return 0;
}

errno_t
ifnet_stat(
	ifnet_t interface,
	struct ifnet_stats_param *stats)
{
	if (interface == NULL) return EINVAL;
	
	lck_spin_lock(dlil_input_lock);

	stats->packets_in = interface->if_data.ifi_ipackets;
	stats->bytes_in = interface->if_data.ifi_ibytes;
	stats->multicasts_in = interface->if_data.ifi_imcasts;
	stats->errors_in = interface->if_data.ifi_ierrors;

	stats->packets_out = interface->if_data.ifi_opackets;
	stats->bytes_out = interface->if_data.ifi_obytes;
	stats->multicasts_out = interface->if_data.ifi_omcasts;
	stats->errors_out = interface->if_data.ifi_oerrors;

	stats->collisions = interface->if_data.ifi_collisions;
	stats->dropped = interface->if_data.ifi_iqdrops;
	stats->no_protocol = interface->if_data.ifi_noproto;

	lck_spin_unlock(dlil_input_lock);
	
	return 0;
}

errno_t
ifnet_touch_lastchange(
	ifnet_t interface)
{
	if (interface == NULL) return EINVAL;
	
	lck_spin_lock(dlil_input_lock);
	TOUCHLASTCHANGE(&interface->if_lastchange);
	lck_spin_unlock(dlil_input_lock);
	
	return 0;
}

errno_t
ifnet_lastchange(
	ifnet_t interface,
	struct timeval *last_change)
{
	if (interface == NULL) return EINVAL;
	
	lck_spin_lock(dlil_input_lock);
	*last_change = interface->if_data.ifi_lastchange;
	lck_spin_unlock(dlil_input_lock);
	
#if IF_LASTCHANGEUPTIME
	/* Crude conversion from uptime to calendar time */
	last_change->tv_sec += boottime_sec();
#endif

	return 0;
}

errno_t
ifnet_get_address_list(
	ifnet_t interface,
	ifaddr_t **addresses)
{
	if (interface == NULL || addresses == NULL) return EINVAL;
	return ifnet_get_address_list_family(interface, addresses, 0);
}

errno_t
ifnet_get_address_list_family(
	ifnet_t interface,
	ifaddr_t **addresses,
	sa_family_t	family)
{
	struct ifnet *ifp;
	int count = 0;
	int cmax = 0;
	
	if (interface == NULL || addresses == NULL) return EINVAL;
	*addresses = NULL;
	
	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet, if_link)
	{
		if (interface && ifp != interface) continue;
		
		ifnet_lock_shared(ifp);
		if ((ifp->if_eflags & IFEF_DETACHING) == 0) {
			if (interface == NULL || interface == ifp)
			{
				struct ifaddr *addr;
				TAILQ_FOREACH(addr, &ifp->if_addrhead, ifa_link)
				{
					if (family == 0 || addr->ifa_addr->sa_family == family)
						cmax++;
				}
			}
		}
		else if (interface != NULL) {
			ifnet_lock_done(ifp);
			ifnet_head_done();
			return ENXIO;
		}
		ifnet_lock_done(ifp);
	}
	
	MALLOC(*addresses, ifaddr_t*, sizeof(ifaddr_t) * (cmax + 1), M_TEMP, M_NOWAIT);
	if (*addresses == NULL) {
		ifnet_head_done();
		return ENOMEM;
	}
	
	TAILQ_FOREACH(ifp, &ifnet, if_link)
	{
		if (interface && ifp != interface) continue;
		
		ifnet_lock_shared(ifp);
		if ((ifp->if_eflags & IFEF_DETACHING) == 0) {
			if (interface == NULL || (struct ifnet*)interface == ifp)
			{
				struct ifaddr *addr;
				TAILQ_FOREACH(addr, &ifp->if_addrhead, ifa_link)
				{
					if (count + 1 > cmax) break;
					if (family == 0 || addr->ifa_addr->sa_family == family) {
						(*addresses)[count] = (ifaddr_t)addr;
						ifaddr_reference((*addresses)[count]);
						count++;
					}
				}
			}
		}
		ifnet_lock_done(ifp);
		if (interface || count == cmax)
			break;
	}
	ifnet_head_done();
	(*addresses)[cmax] = 0;
	
	return 0;
}

void
ifnet_free_address_list(
	ifaddr_t *addresses)
{
	int i;
	
	if (addresses == NULL) return;
	
	for (i = 0; addresses[i] != NULL; i++)
	{
		ifaddr_release(addresses[i]);
	}
	
	FREE(addresses, M_TEMP);
}

void*
ifnet_lladdr(
	ifnet_t	interface)
{
	if (interface == NULL) return NULL;
	return LLADDR(SDL(interface->if_addrhead.tqh_first->ifa_addr));
}

errno_t
ifnet_llbroadcast_copy_bytes(
	ifnet_t	interface,
	void	*addr,
	size_t	buffer_len,
	size_t	*out_len)
{
	if (interface == NULL || addr == NULL || out_len == NULL) return EINVAL;
	
	*out_len = interface->if_broadcast.length;
	
	if (buffer_len < interface->if_broadcast.length) {
		return EMSGSIZE;
	}
	
	if (interface->if_broadcast.length == 0)
		return ENXIO;
	
	if (interface->if_broadcast.length <= sizeof(interface->if_broadcast.u.buffer)) {
		bcopy(interface->if_broadcast.u.buffer, addr, interface->if_broadcast.length);
	}
	else {
		bcopy(interface->if_broadcast.u.ptr, addr, interface->if_broadcast.length);
	}
	
	return 0;
}

errno_t
ifnet_lladdr_copy_bytes(
	ifnet_t	interface,
	void*	lladdr,
	size_t	lladdr_len)
{
	struct sockaddr_dl *sdl;
	if (interface == NULL || lladdr == NULL) return EINVAL;
	
	sdl = SDL(interface->if_addrhead.tqh_first->ifa_addr);
	
	while (1) {
		if (lladdr_len != sdl->sdl_alen) {
			bzero(lladdr, lladdr_len);
			return EMSGSIZE;
		}
		bcopy(LLADDR(sdl), lladdr, lladdr_len);
		if (bcmp(lladdr, LLADDR(sdl), lladdr_len) == 0 &&
			lladdr_len == sdl->sdl_alen)
			break;
	}
	return 0;
}

static errno_t
ifnet_set_lladdr_internal(
	ifnet_t interface,
	const void *lladdr,
	size_t lladdr_len,
	u_char new_type,
	int apply_type)
{
	struct ifaddr *ifa;
	struct sockaddr_dl	*sdl;
	errno_t	error = 0;
	
	if (interface == NULL) return EINVAL;
	
	if (lladdr_len != 0 && (lladdr_len != interface->if_addrlen || lladdr == 0))
		return EINVAL;
	
	ifnet_head_lock_shared();
	ifa = ifnet_addrs[interface->if_index - 1];
	if (ifa != NULL) {
		sdl = (struct sockaddr_dl*)ifa->ifa_addr;
		if (lladdr_len != 0) {
			bcopy(lladdr, LLADDR(sdl), lladdr_len);
		}
		else {
			bzero(LLADDR(sdl), interface->if_addrlen);
		}
		sdl->sdl_alen = lladdr_len;
		
		if (apply_type) {
			sdl->sdl_type = new_type;
		}
	}
	else {
		error = ENXIO;
	}
	ifnet_head_done();
	
	/* Generate a kernel event */
	if (error == 0) {
		dlil_post_msg(interface, KEV_DL_SUBCLASS,
			KEV_DL_LINK_ADDRESS_CHANGED, NULL, 0);
	}
	
	return error;
}

errno_t
ifnet_set_lladdr(
	ifnet_t interface,
	const void* lladdr,
	size_t lladdr_len)
{
	return ifnet_set_lladdr_internal(interface, lladdr, lladdr_len, 0, 0);
}

errno_t
ifnet_set_lladdr_and_type(
	ifnet_t interface,
	const void* lladdr,
	size_t lladdr_len,
	u_char type)
{
	return ifnet_set_lladdr_internal(interface, lladdr, lladdr_len, type, 1);
}

errno_t
ifnet_add_multicast(
	ifnet_t interface,
	const struct sockaddr *maddr,
	ifmultiaddr_t *address)
{
	if (interface == NULL || maddr == NULL) return EINVAL;
	return if_addmulti(interface, maddr, address);
}

errno_t
ifnet_remove_multicast(
	ifmultiaddr_t address)
{
	if (address == NULL) return EINVAL;
	return if_delmultiaddr(address, 0);
}

errno_t ifnet_get_multicast_list(ifnet_t interface, ifmultiaddr_t **addresses)
{
	int count = 0;
	int cmax = 0;
	struct ifmultiaddr *addr;
	int lock;
	
	if (interface == NULL || addresses == NULL)
		return EINVAL;
	
	lock = (interface->if_lock != 0);
	if (lock) ifnet_lock_shared(interface);
	if ((interface->if_eflags & IFEF_DETACHING) == 0) {
		LIST_FOREACH(addr, &interface->if_multiaddrs, ifma_link)
		{
			cmax++;
		}
	}
	else {
		if (lock) ifnet_lock_done(interface);
		return ENXIO;
	}
	
	MALLOC(*addresses, ifmultiaddr_t*, sizeof(ifmultiaddr_t) * (cmax + 1), M_TEMP, M_NOWAIT);
	if (*addresses == NULL) return ENOMEM;
	
	LIST_FOREACH(addr, &interface->if_multiaddrs, ifma_link)
	{
		if (count + 1 > cmax)
			break;
		(*addresses)[count] = (ifmultiaddr_t)addr;
		ifmaddr_reference((*addresses)[count]);
		count++;
	}
	(*addresses)[cmax] = 0;
	if (lock) ifnet_lock_done(interface);
	
	return 0;
}

void
ifnet_free_multicast_list(
	ifmultiaddr_t *addresses)
{
	int i;
	
	if (addresses == NULL) return;
	
	for (i = 0; addresses[i] != NULL; i++)
	{
		ifmaddr_release(addresses[i]);
	}
	
	FREE(addresses, M_TEMP);
}

errno_t
ifnet_find_by_name(
	const char *ifname,
	ifnet_t *interface)
{
	struct ifnet *ifp;
	int	namelen;
	
	if (ifname == NULL) return EINVAL;
	
	namelen = strlen(ifname);
	
	*interface = NULL;
	
	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet, if_link)
	{
		struct ifaddr *ifa = ifnet_addrs[ifp->if_index - 1];
		struct sockaddr_dl *ll_addr;
		
		if (!ifa || !ifa->ifa_addr)
			continue;
		
		ll_addr = (struct sockaddr_dl *)ifa->ifa_addr;
		
		if ((ifp->if_eflags & IFEF_DETACHING) == 0 &&
			namelen == ll_addr->sdl_nlen &&
			(strncmp(ll_addr->sdl_data, ifname, ll_addr->sdl_nlen) == 0))
		{
			break;
		}
	}
	if (ifp) {
		*interface = ifp;
		ifnet_reference(*interface);
	}
	ifnet_head_done();
	
	return (ifp == NULL) ? ENXIO : 0;
}

errno_t
ifnet_list_get(
	ifnet_family_t family,
	ifnet_t **list,
	u_int32_t *count)
{
	struct ifnet *ifp;
	u_int32_t cmax = 0;
	*count = 0;
	errno_t	result = 0;
	
	if (list == NULL || count == NULL) return EINVAL;
	
	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet, if_link)
	{
		if (ifp->if_eflags & IFEF_DETACHING) continue;
		if (family == 0 || ifp->if_family == family)
			cmax++;
	}
	
	if (cmax == 0)
		result = ENXIO;
	
	if (result == 0) {
		MALLOC(*list, ifnet_t*, sizeof(ifnet_t) * (cmax + 1), M_TEMP, M_NOWAIT);
		if (*list == NULL)
			result = ENOMEM;
	}

	if (result == 0) {
		TAILQ_FOREACH(ifp, &ifnet, if_link)
		{
			if (ifp->if_eflags & IFEF_DETACHING) continue;
			if (*count + 1 > cmax) break;
			if (family == 0 || ((ifnet_family_t)ifp->if_family) == family)
			{
				(*list)[*count] = (ifnet_t)ifp;
				ifnet_reference((*list)[*count]);
				(*count)++;
			}
		}
		(*list)[*count] = NULL;
	}
	ifnet_head_done();
	
	return 0;
}

void
ifnet_list_free(
	ifnet_t *interfaces)
{
	int i;
	
	if (interfaces == NULL) return;
	
	for (i = 0; interfaces[i]; i++)
	{
		ifnet_release(interfaces[i]);
	}
	
	FREE(interfaces, M_TEMP);
}

/****************************************************************************/
/* ifaddr_t accessors														*/
/****************************************************************************/

errno_t
ifaddr_reference(
	ifaddr_t ifa)
{
	if (ifa == NULL) return EINVAL;
	ifaref(ifa);
	return 0;
}

errno_t
ifaddr_release(
	ifaddr_t ifa)
{
	if (ifa == NULL) return EINVAL;
	ifafree(ifa);
	return 0;
}

sa_family_t
ifaddr_address_family(
	ifaddr_t ifa)
{
	if (ifa && ifa->ifa_addr)
		return ifa->ifa_addr->sa_family;
	
	return 0;
}

errno_t
ifaddr_address(
	ifaddr_t ifa,
	struct sockaddr *out_addr,
	u_int32_t addr_size)
{
	u_int32_t copylen;
	
	if (ifa == NULL || out_addr == NULL) return EINVAL;
	if (ifa->ifa_addr == NULL) return ENOTSUP;
	
	copylen = (addr_size >= ifa->ifa_addr->sa_len) ? ifa->ifa_addr->sa_len : addr_size;
	bcopy(ifa->ifa_addr, out_addr, copylen);
	
	if (ifa->ifa_addr->sa_len > addr_size) return EMSGSIZE;
	
	return 0;
}

errno_t
ifaddr_dstaddress(
	ifaddr_t ifa,
	struct sockaddr *out_addr,
	u_int32_t addr_size)
{
	u_int32_t copylen;
	if (ifa == NULL || out_addr == NULL) return EINVAL;
	if (ifa->ifa_dstaddr == NULL) return ENOTSUP;
	
	copylen = (addr_size >= ifa->ifa_dstaddr->sa_len) ? ifa->ifa_dstaddr->sa_len : addr_size;
	bcopy(ifa->ifa_dstaddr, out_addr, copylen);

	if (ifa->ifa_dstaddr->sa_len > addr_size) return EMSGSIZE;
	
	return 0;
}

errno_t
ifaddr_netmask(
	ifaddr_t ifa,
	struct sockaddr *out_addr,
	u_int32_t addr_size)
{
	u_int32_t copylen;
	if (ifa == NULL || out_addr == NULL) return EINVAL;
	if (ifa->ifa_netmask == NULL) return ENOTSUP;
	
	copylen = addr_size >= ifa->ifa_netmask->sa_len ? ifa->ifa_netmask->sa_len : addr_size;
	bcopy(ifa->ifa_netmask, out_addr, copylen);
	
	if (ifa->ifa_netmask->sa_len > addr_size) return EMSGSIZE;
	
	return 0;
}

ifnet_t
ifaddr_ifnet(
	ifaddr_t ifa)
{
	struct ifnet *ifp;
	if (ifa == NULL) return NULL;
	ifp = ifa->ifa_ifp;
	
	return (ifnet_t)ifp;
}

ifaddr_t
ifaddr_withaddr(
	const struct sockaddr* address)
{
	if (address == NULL) return NULL;
	return ifa_ifwithaddr(address);
}

ifaddr_t
ifaddr_withdstaddr(
	const struct sockaddr* address)
{
	if (address == NULL) return NULL;
	return ifa_ifwithdstaddr(address);
}

ifaddr_t
ifaddr_withnet(
	const struct sockaddr* net)
{
	if (net == NULL) return NULL;
	return ifa_ifwithnet(net);
}

ifaddr_t
ifaddr_withroute(
	int flags,
	const struct sockaddr* destination,
	const struct sockaddr* gateway)
{
	if (destination == NULL || gateway == NULL) return NULL;
	return ifa_ifwithroute(flags, destination, gateway);
}

ifaddr_t
ifaddr_findbestforaddr(
	const struct sockaddr *addr,
	ifnet_t interface)
{
	if (addr == NULL || interface == NULL) return NULL;
	return ifaof_ifpforaddr(addr, interface);
}

errno_t
ifmaddr_reference(
	ifmultiaddr_t ifmaddr)
{
	if (ifmaddr == NULL) return EINVAL;
	ifma_reference(ifmaddr);
	return 0;
}

errno_t
ifmaddr_release(
	ifmultiaddr_t ifmaddr)
{
	if (ifmaddr == NULL) return EINVAL;
	ifma_release(ifmaddr);	
	return 0;
}

errno_t
ifmaddr_address(
	ifmultiaddr_t ifmaddr,
	struct sockaddr *out_addr,
	u_int32_t addr_size)
{
	u_int32_t copylen;
	
	if (ifmaddr == NULL || out_addr == NULL) return EINVAL;
	if (ifmaddr->ifma_addr == NULL) return ENOTSUP;
	
	copylen = addr_size >= ifmaddr->ifma_addr->sa_len ? ifmaddr->ifma_addr->sa_len : addr_size;
	bcopy(ifmaddr->ifma_addr, out_addr, copylen);
	
	if (ifmaddr->ifma_addr->sa_len > addr_size) return EMSGSIZE;
	
	return 0;
}

errno_t
ifmaddr_lladdress(
	ifmultiaddr_t ifmaddr,
	struct sockaddr *out_addr,
	u_int32_t addr_size)
{
	if (ifmaddr == NULL || out_addr == NULL) return EINVAL;
	if (ifmaddr->ifma_ll == NULL) return ENOTSUP;
	
	return ifmaddr_address(ifmaddr->ifma_ll, out_addr, addr_size);
}

ifnet_t
ifmaddr_ifnet(
	ifmultiaddr_t ifmaddr)
{
	if (ifmaddr == NULL || ifmaddr->ifma_ifp == NULL) return NULL;
	return ifmaddr->ifma_ifp;
}
