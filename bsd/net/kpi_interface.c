/*
 * Copyright (c) 2004-2010 Apple Inc. All rights reserved.
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

#include "kpi_interface.h"

#include <sys/queue.h>
#include <sys/param.h>	/* for definition of NULL */
#include <kern/debug.h> /* for panic */
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/kern_event.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/kpi_mbuf.h>
#include <sys/mcache.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/dlil.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <kern/locks.h>

#include "net/net_str_id.h"

#if IF_LASTCHANGEUPTIME
#define TOUCHLASTCHANGE(__if_lastchange) microuptime(__if_lastchange)
#else
#define TOUCHLASTCHANGE(__if_lastchange) microtime(__if_lastchange)
#endif

static errno_t
ifnet_list_get_common(ifnet_family_t, boolean_t, ifnet_t **, u_int32_t *);

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

static __inline__ void*
_cast_non_const(const void * ptr) {
	union {
		const void*		cval;
		void*			val;
	} ret;
	
	ret.cval = ptr;
	return (ret.val);
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
		/*
		 * Cast ifp->if_name as non const. dlil_if_acquire sets it up
		 * to point to storage of at least IFNAMSIZ bytes. It is safe
		 * to write to this.
		 */
		strncpy(_cast_non_const(ifp->if_name), init->name, IFNAMSIZ);
		ifp->if_type = init->type;
		ifp->if_family = init->family;
		ifp->if_unit = init->unit;
		ifp->if_output = init->output;
		ifp->if_demux = init->demux;
		ifp->if_add_proto = init->add_proto;
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
ifnet_reference(ifnet_t ifp)
{
	return (dlil_if_ref(ifp));
}

errno_t
ifnet_release(ifnet_t ifp)
{
	return (dlil_if_free(ifp));
}

errno_t 
ifnet_interface_family_find(const char *module_string, ifnet_family_t *family_id)
{
	if (module_string == NULL || family_id == NULL)
		return EINVAL;
	return net_str_id_find_internal(module_string, family_id, NSI_IF_FAM_ID, 1);
	
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
ifnet_set_flags(ifnet_t interface, u_int16_t new_flags, u_int16_t mask)
{
	if (interface == NULL)
		return (EINVAL);

	ifnet_lock_exclusive(interface);

	/* If we are modifying the up/down state, call if_updown */
	if ((mask & IFF_UP) != 0) {
		if_updown(interface, (new_flags & IFF_UP) == IFF_UP);
	}

	interface->if_flags = (new_flags & mask) | (interface->if_flags & ~mask);
	ifnet_lock_done(interface);

	return (0);
}

u_int16_t
ifnet_flags(
	ifnet_t interface)
{
	return interface == NULL ? 0 : interface->if_flags;
}

errno_t
ifnet_set_eflags(ifnet_t interface, u_int32_t new_flags, u_int32_t mask)
{
	if (interface == NULL)
		return (EINVAL);

	ifnet_lock_exclusive(interface);
	interface->if_eflags = (new_flags & mask) | (interface->if_eflags & ~mask);
	ifnet_lock_done(interface);

	return (0);
}

u_int32_t
ifnet_eflags(
	ifnet_t interface)
{
	return interface == NULL ? 0 : interface->if_eflags;
}

errno_t
ifnet_set_idle_flags_locked(ifnet_t ifp, u_int32_t new_flags, u_int32_t mask)
{
	int before, after;

	if (ifp == NULL)
		return (EINVAL);

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_EXCLUSIVE);

	/*
	 * If this is called prior to ifnet attach, the actual work will
	 * be done at attach time.  Otherwise, if it is called after
	 * ifnet detach, then it is a no-op.
	 */
	if (!ifnet_is_attached(ifp, 0)) {
		ifp->if_idle_new_flags = new_flags;
		ifp->if_idle_new_flags_mask = mask;
		return (0);
	} else {
		ifp->if_idle_new_flags = ifp->if_idle_new_flags_mask = 0;
	}

	before = ifp->if_idle_flags;
	ifp->if_idle_flags = (new_flags & mask) | (ifp->if_idle_flags & ~mask);
	after = ifp->if_idle_flags;

	if ((after - before) < 0 && ifp->if_idle_flags == 0 &&
	    ifp->if_want_aggressive_drain != 0) {
		ifp->if_want_aggressive_drain = 0;
		if (ifnet_aggressive_drainers == 0)
			panic("%s: ifp=%p negative aggdrain!", __func__, ifp);
		if (--ifnet_aggressive_drainers == 0)
			rt_aggdrain(0);
	} else if ((after - before) > 0 && ifp->if_want_aggressive_drain == 0) {
		ifp->if_want_aggressive_drain++;
		if (++ifnet_aggressive_drainers == 0)
			panic("%s: ifp=%p wraparound aggdrain!", __func__, ifp);
		else if (ifnet_aggressive_drainers == 1)
			rt_aggdrain(1);
	}

	return (0);
}

errno_t
ifnet_set_idle_flags(ifnet_t ifp, u_int32_t new_flags, u_int32_t mask)
{
	errno_t err;

	lck_mtx_lock(rnh_lock);
	ifnet_lock_exclusive(ifp);
	err = ifnet_set_idle_flags_locked(ifp, new_flags, mask);
	ifnet_lock_done(ifp);
	lck_mtx_unlock(rnh_lock);

	return (err);
}

u_int32_t
ifnet_idle_flags(ifnet_t ifp)
{
	return ((ifp == NULL) ? 0 : ifp->if_idle_flags);
}

errno_t ifnet_set_capabilities_supported(ifnet_t ifp, u_int32_t new_caps,
    u_int32_t mask)
{
	errno_t error = 0;
	int tmp;

	if (ifp == NULL)
		return EINVAL;
	
	ifnet_lock_exclusive(ifp);
	tmp = (new_caps & mask) | (ifp->if_capabilities & ~mask);
	if ((tmp & ~IFCAP_VALID))
		error = EINVAL;
	else
		ifp->if_capabilities = tmp;
	ifnet_lock_done(ifp);
	
	return error;
}

u_int32_t ifnet_capabilities_supported(ifnet_t ifp)
{
	return ((ifp == NULL) ? 0 : ifp->if_capabilities);
}


errno_t ifnet_set_capabilities_enabled(ifnet_t ifp, u_int32_t new_caps,
    u_int32_t mask)
{
	errno_t error = 0;
	int tmp;
	struct kev_msg        ev_msg;
	struct net_event_data ev_data;

	if (ifp == NULL)
		return EINVAL;
	
	ifnet_lock_exclusive(ifp);
	tmp = (new_caps & mask) | (ifp->if_capenable & ~mask);
	if ((tmp & ~IFCAP_VALID) || (tmp & ~ifp->if_capabilities))
		error = EINVAL;
	else
		ifp->if_capenable = tmp;
	ifnet_lock_done(ifp);
	
	/* Notify application of the change */
	bzero(&ev_data, sizeof(struct net_event_data));
	bzero(&ev_msg, sizeof(struct kev_msg));
	ev_msg.vendor_code    = KEV_VENDOR_APPLE;
	ev_msg.kev_class      = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass   = KEV_DL_SUBCLASS;

	ev_msg.event_code = KEV_DL_IFCAP_CHANGED;
	strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);
	ev_data.if_family = ifp->if_family;
	ev_data.if_unit   = (u_int32_t) ifp->if_unit;
	ev_msg.dv[0].data_length = sizeof(struct net_event_data);
	ev_msg.dv[0].data_ptr    = &ev_data;
	ev_msg.dv[1].data_length = 0;
	kev_post_msg(&ev_msg);

	return error;
}

u_int32_t ifnet_capabilities_enabled(ifnet_t ifp)
{
	return ((ifp == NULL) ? 0 : ifp->if_capenable);
	
	return 0;
}

static const ifnet_offload_t offload_mask = IFNET_CSUM_IP | IFNET_CSUM_TCP |
			IFNET_CSUM_UDP | IFNET_CSUM_FRAGMENT | IFNET_IP_FRAGMENT |
			IFNET_CSUM_TCPIPV6 | IFNET_CSUM_UDPIPV6 | IFNET_IPV6_FRAGMENT |
			IFNET_CSUM_SUM16 | IFNET_VLAN_TAGGING | IFNET_VLAN_MTU |
			IFNET_MULTIPAGES | IFNET_TSO_IPV4 | IFNET_TSO_IPV6;

static const ifnet_offload_t any_offload_csum = IFNET_CSUM_IP | IFNET_CSUM_TCP |
			IFNET_CSUM_UDP | IFNET_CSUM_FRAGMENT |
			IFNET_CSUM_TCPIPV6 | IFNET_CSUM_UDPIPV6 |
			IFNET_CSUM_SUM16;


errno_t
ifnet_set_offload(ifnet_t interface, ifnet_offload_t offload)
{
	u_int32_t ifcaps = 0;
	
	if (interface == NULL)
		return (EINVAL);

	ifnet_lock_exclusive(interface);
	interface->if_hwassist = (offload & offload_mask);	
	ifnet_lock_done(interface);

	if ((offload & any_offload_csum))
		ifcaps |= IFCAP_HWCSUM;
	if ((offload & IFNET_TSO_IPV4))
		ifcaps |= IFCAP_TSO4;
	if ((offload & IFNET_TSO_IPV6))
		ifcaps |= IFCAP_TSO6;
	if ((offload & IFNET_VLAN_MTU))
		ifcaps |= IFCAP_VLAN_MTU;
	if ((offload & IFNET_VLAN_TAGGING))
		ifcaps |= IFCAP_VLAN_HWTAGGING;
	if (ifcaps != 0) {
		(void) ifnet_set_capabilities_supported(interface, ifcaps, IFCAP_VALID);
		(void) ifnet_set_capabilities_enabled(interface, ifcaps, IFCAP_VALID);
	}

	return (0);
}

ifnet_offload_t
ifnet_offload(
	ifnet_t interface)
{
	return interface == NULL ? 0 : (interface->if_hwassist & offload_mask);
}

errno_t 
ifnet_set_tso_mtu(
	ifnet_t interface, 
	sa_family_t	family,
	u_int32_t mtuLen)
{
	errno_t error = 0;

	if (interface == NULL) return EINVAL;

	if (mtuLen < interface->if_mtu)
		return EINVAL;
	

	switch (family) {

		case AF_INET: 
			if (interface->if_hwassist & IFNET_TSO_IPV4)
				interface->if_tso_v4_mtu = mtuLen;
			else
				error = EINVAL;
			break;

		case AF_INET6:
			if (interface->if_hwassist & IFNET_TSO_IPV6)
				interface->if_tso_v6_mtu = mtuLen;
			else
				error = EINVAL;
			break;

		default:
			error = EPROTONOSUPPORT;
	}

	return error;
}
	
errno_t 
ifnet_get_tso_mtu(
	ifnet_t interface, 
	sa_family_t	family,
	u_int32_t *mtuLen)
{
	errno_t error = 0;

	if (interface == NULL || mtuLen == NULL) return EINVAL;
	
	switch (family) {

		case AF_INET: 
			if (interface->if_hwassist & IFNET_TSO_IPV4)
				*mtuLen = interface->if_tso_v4_mtu;
			else
				error = EINVAL;
			break;

		case AF_INET6:
			if (interface->if_hwassist & IFNET_TSO_IPV6)
				*mtuLen = interface->if_tso_v6_mtu;
			else
				error = EINVAL;
			break;
		default:
			error = EPROTONOSUPPORT;
	}

	return error;
}

errno_t
ifnet_set_wake_flags(ifnet_t interface, u_int32_t properties, u_int32_t mask)
{
	struct kev_msg        ev_msg;
	struct net_event_data ev_data;

	bzero(&ev_data, sizeof(struct net_event_data));
	bzero(&ev_msg, sizeof(struct kev_msg));
	if (interface == NULL)
		return EINVAL;

	/* Do not accept wacky values */
	if ((properties & mask) & ~IF_WAKE_VALID_FLAGS)
		return EINVAL;

	ifnet_lock_exclusive(interface);

	interface->if_wake_properties = (properties & mask) | (interface->if_wake_properties & ~mask);

	ifnet_lock_done(interface);

	(void) ifnet_touch_lastchange(interface);

	/* Notify application of the change */
	ev_msg.vendor_code    = KEV_VENDOR_APPLE;
	ev_msg.kev_class      = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass   = KEV_DL_SUBCLASS;

	ev_msg.event_code = KEV_DL_WAKEFLAGS_CHANGED;
	strlcpy(&ev_data.if_name[0], interface->if_name, IFNAMSIZ);
	ev_data.if_family = interface->if_family;
	ev_data.if_unit   = (u_int32_t) interface->if_unit;
	ev_msg.dv[0].data_length = sizeof(struct net_event_data);
	ev_msg.dv[0].data_ptr    = &ev_data;
	ev_msg.dv[1].data_length = 0;
	kev_post_msg(&ev_msg);

	return 0;
}

u_int32_t
ifnet_get_wake_flags(ifnet_t interface)
{
	return interface == NULL ? 0 : interface->if_wake_properties;
}

/*
 * Should MIB data store a copy?
 */
errno_t
ifnet_set_link_mib_data(ifnet_t interface, void *mibData, u_int32_t mibLen)
{
	if (interface == NULL)
		return (EINVAL);

	ifnet_lock_exclusive(interface);
	interface->if_linkmib = (void*)mibData;
	interface->if_linkmiblen = mibLen;
	ifnet_lock_done(interface);
	return (0);
}

errno_t
ifnet_get_link_mib_data(ifnet_t interface, void *mibData, u_int32_t *mibLen)
{
	errno_t	result = 0;

	if (interface == NULL)
		return (EINVAL);

	ifnet_lock_shared(interface);
	if (*mibLen < interface->if_linkmiblen)
		result = EMSGSIZE;
	if (result == 0 && interface->if_linkmib == NULL)
		result = ENOTSUP;

	if (result == 0) {
		*mibLen = interface->if_linkmiblen;
		bcopy(interface->if_linkmib, mibData, *mibLen);
	}
	ifnet_lock_done(interface);

	return (result);
}

u_int32_t
ifnet_get_link_mib_data_length(
	ifnet_t interface)
{
	return interface == NULL ? 0 : interface->if_linkmiblen;
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
	if (interface == NULL || m == NULL) {
		if (m)
			mbuf_freem_list(m);
		return EINVAL;
	}
	return dlil_output(interface, protocol_family, m, NULL, NULL, 1);
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
ifnet_set_typelen(ifnet_t interface, u_char typelen)
{
	ifnet_lock_exclusive(interface);
	interface->if_data.ifi_typelen = typelen;
	ifnet_lock_done(interface);
	return (0);
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
ifnet_stat_increment(ifnet_t interface,
    const struct ifnet_stat_increment_param *counts)
{
	if (interface == NULL)
		return (EINVAL);

	atomic_add_64(&interface->if_data.ifi_ipackets, counts->packets_in);
	atomic_add_64(&interface->if_data.ifi_ibytes, counts->bytes_in);
	atomic_add_64(&interface->if_data.ifi_ierrors, counts->errors_in);

	atomic_add_64(&interface->if_data.ifi_opackets, counts->packets_out);
	atomic_add_64(&interface->if_data.ifi_obytes, counts->bytes_out);
	atomic_add_64(&interface->if_data.ifi_oerrors, counts->errors_out);

	atomic_add_64(&interface->if_data.ifi_collisions, counts->collisions);
	atomic_add_64(&interface->if_data.ifi_iqdrops, counts->dropped);

	/* Touch the last change time. */
	TOUCHLASTCHANGE(&interface->if_lastchange);

	return (0);
}

errno_t
ifnet_stat_increment_in(ifnet_t interface, u_int32_t packets_in,
    u_int32_t bytes_in, u_int32_t errors_in)
{
	if (interface == NULL)
		return (EINVAL);

	atomic_add_64(&interface->if_data.ifi_ipackets, packets_in);
	atomic_add_64(&interface->if_data.ifi_ibytes, bytes_in);
	atomic_add_64(&interface->if_data.ifi_ierrors, errors_in);

	TOUCHLASTCHANGE(&interface->if_lastchange);

	return (0);
}

errno_t
ifnet_stat_increment_out(ifnet_t interface, u_int32_t packets_out,
    u_int32_t bytes_out, u_int32_t errors_out)
{
	if (interface == NULL)
		return (EINVAL);

	atomic_add_64(&interface->if_data.ifi_opackets, packets_out);
	atomic_add_64(&interface->if_data.ifi_obytes, bytes_out);
	atomic_add_64(&interface->if_data.ifi_oerrors, errors_out);

	TOUCHLASTCHANGE(&interface->if_lastchange);

	return (0);
}

errno_t
ifnet_set_stat(ifnet_t interface, const struct ifnet_stats_param *stats)
{
	if (interface == NULL)
		return (EINVAL);

	atomic_set_64(&interface->if_data.ifi_ipackets, stats->packets_in);
	atomic_set_64(&interface->if_data.ifi_ibytes, stats->bytes_in);
	atomic_set_64(&interface->if_data.ifi_imcasts, stats->multicasts_in);
	atomic_set_64(&interface->if_data.ifi_ierrors, stats->errors_in);

	atomic_set_64(&interface->if_data.ifi_opackets, stats->packets_out);
	atomic_set_64(&interface->if_data.ifi_obytes, stats->bytes_out);
	atomic_set_64(&interface->if_data.ifi_omcasts, stats->multicasts_out);
	atomic_set_64(&interface->if_data.ifi_oerrors, stats->errors_out);

	atomic_set_64(&interface->if_data.ifi_collisions, stats->collisions);
	atomic_set_64(&interface->if_data.ifi_iqdrops, stats->dropped);
	atomic_set_64(&interface->if_data.ifi_noproto, stats->no_protocol);

	/* Touch the last change time. */
	TOUCHLASTCHANGE(&interface->if_lastchange);

	return 0;
}

errno_t
ifnet_stat(ifnet_t interface, struct ifnet_stats_param *stats)
{
	if (interface == NULL)
		return (EINVAL);

	atomic_get_64(stats->packets_in, &interface->if_data.ifi_ipackets);
	atomic_get_64(stats->bytes_in, &interface->if_data.ifi_ibytes);
	atomic_get_64(stats->multicasts_in, &interface->if_data.ifi_imcasts);
	atomic_get_64(stats->errors_in, &interface->if_data.ifi_ierrors);

	atomic_get_64(stats->packets_out, &interface->if_data.ifi_opackets);
	atomic_get_64(stats->bytes_out, &interface->if_data.ifi_obytes);
	atomic_get_64(stats->multicasts_out, &interface->if_data.ifi_omcasts);
	atomic_get_64(stats->errors_out, &interface->if_data.ifi_oerrors);

	atomic_get_64(stats->collisions, &interface->if_data.ifi_collisions);
	atomic_get_64(stats->dropped, &interface->if_data.ifi_iqdrops);
	atomic_get_64(stats->no_protocol, &interface->if_data.ifi_noproto);

	return (0);
}

errno_t
ifnet_touch_lastchange(ifnet_t interface)
{
	if (interface == NULL)
		return (EINVAL);

	TOUCHLASTCHANGE(&interface->if_lastchange);

	return (0);
}

errno_t
ifnet_lastchange(ifnet_t interface, struct timeval *last_change)
{
	if (interface == NULL)
		return (EINVAL);

	*last_change = interface->if_data.ifi_lastchange;
#if IF_LASTCHANGEUPTIME
	/* Crude conversion from uptime to calendar time */
	last_change->tv_sec += boottime_sec();
#endif
	return (0);
}

errno_t
ifnet_get_address_list(ifnet_t interface, ifaddr_t **addresses)
{
	return (addresses == NULL ? EINVAL :
	    ifnet_get_address_list_family(interface, addresses, 0));
}

struct ifnet_addr_list {
	SLIST_ENTRY(ifnet_addr_list)	ifal_le;
	struct ifaddr			*ifal_ifa;
};

errno_t
ifnet_get_address_list_family(ifnet_t interface, ifaddr_t **addresses,
    sa_family_t family)
{
	return (ifnet_get_address_list_family_internal(interface, addresses,
	    family, 0, M_NOWAIT));
}

__private_extern__ errno_t
ifnet_get_address_list_family_internal(ifnet_t interface, ifaddr_t **addresses,
    sa_family_t family, int detached, int how)
{
	SLIST_HEAD(, ifnet_addr_list) ifal_head;
	struct ifnet_addr_list *ifal, *ifal_tmp;
	struct ifnet *ifp;
	int count = 0;
	errno_t err = 0;

	SLIST_INIT(&ifal_head);

	if (addresses == NULL) {
		err = EINVAL;
		goto done;
	}
	*addresses = NULL;

	if (detached) {
		/*
		 * Interface has been detached, so skip the lookup
		 * at ifnet_head and go directly to inner loop.
		 */
		ifp = interface;
		if (ifp == NULL) {
			err = EINVAL;
			goto done;
		}
		goto one;
	}

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		if (interface != NULL && ifp != interface)
			continue;
one:
		ifnet_lock_shared(ifp);
		if (interface == NULL || interface == ifp) {
			struct ifaddr *ifa;
			TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
				IFA_LOCK(ifa);
				if (family != 0 &&
				    ifa->ifa_addr->sa_family != family) {
					IFA_UNLOCK(ifa);
					continue;
				}
				MALLOC(ifal, struct ifnet_addr_list *,
				    sizeof (*ifal), M_TEMP, how);
				if (ifal == NULL) {
					IFA_UNLOCK(ifa);
					ifnet_lock_done(ifp);
					if (!detached)
						ifnet_head_done();
					err = ENOMEM;
					goto done;
				}
				ifal->ifal_ifa = ifa;
				IFA_ADDREF_LOCKED(ifa);
				SLIST_INSERT_HEAD(&ifal_head, ifal, ifal_le);
				++count;
				IFA_UNLOCK(ifa);
			}
		}
		ifnet_lock_done(ifp);
		if (detached)
			break;
	}
	if (!detached)
		ifnet_head_done();

	if (count == 0) {
		err = ENXIO;
		goto done;
	}
	MALLOC(*addresses, ifaddr_t *, sizeof (ifaddr_t) * (count + 1),
	    M_TEMP, how);
	if (*addresses == NULL) {
		err = ENOMEM;
		goto done;
	}
	bzero(*addresses, sizeof (ifaddr_t) * (count + 1));

done:
	SLIST_FOREACH_SAFE(ifal, &ifal_head, ifal_le, ifal_tmp) {
		SLIST_REMOVE(&ifal_head, ifal, ifnet_addr_list, ifal_le);
		if (err == 0)
			(*addresses)[--count] = ifal->ifal_ifa;
		else
			IFA_REMREF(ifal->ifal_ifa);
		FREE(ifal, M_TEMP);
	}

	return (err);
}

void
ifnet_free_address_list(ifaddr_t *addresses)
{
	int i;

	if (addresses == NULL)
		return;

	for (i = 0; addresses[i] != NULL; i++)
		IFA_REMREF(addresses[i]);

	FREE(addresses, M_TEMP);
}

void *
ifnet_lladdr(ifnet_t interface)
{
	struct ifaddr *ifa;
	void *lladdr;

	if (interface == NULL)
		return (NULL);

	/*
	 * if_lladdr points to the permanent link address of
	 * the interface; it never gets deallocated.
	 */
	ifa = interface->if_lladdr;
	IFA_LOCK_SPIN(ifa);
	lladdr = LLADDR(SDL(ifa->ifa_addr));
	IFA_UNLOCK(ifa);

	return (lladdr);
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
ifnet_lladdr_copy_bytes(ifnet_t interface, void *lladdr, size_t	lladdr_len)
{
	struct sockaddr_dl *sdl;
	struct ifaddr *ifa;

	if (interface == NULL || lladdr == NULL)
		return (EINVAL);

	/*
	 * if_lladdr points to the permanent link address of
	 * the interface; it never gets deallocated.
	 */
	ifa = interface->if_lladdr;
	IFA_LOCK_SPIN(ifa);
	sdl = SDL(ifa->ifa_addr);
	if (lladdr_len != sdl->sdl_alen) {
		bzero(lladdr, lladdr_len);
		IFA_UNLOCK(ifa);
		return (EMSGSIZE);
	}
	bcopy(LLADDR(sdl), lladdr, lladdr_len);
	IFA_UNLOCK(ifa);

	return (0);
}

static errno_t
ifnet_set_lladdr_internal(ifnet_t interface, const void *lladdr,
    size_t lladdr_len, u_char new_type, int apply_type)
{
	struct ifaddr *ifa;
	errno_t	error = 0;

	if (interface == NULL)
		return (EINVAL);

	ifnet_head_lock_shared();
	ifnet_lock_exclusive(interface);
	if (lladdr_len != 0 &&
	    (lladdr_len != interface->if_addrlen || lladdr == 0)) {
		ifnet_lock_done(interface);
		ifnet_head_done();
		return (EINVAL);
	}
	ifa = ifnet_addrs[interface->if_index - 1];
	if (ifa != NULL) {
		struct sockaddr_dl *sdl;

		IFA_LOCK_SPIN(ifa);
		sdl = (struct sockaddr_dl*)ifa->ifa_addr;
		if (lladdr_len != 0) {
			bcopy(lladdr, LLADDR(sdl), lladdr_len);
		} else {
			bzero(LLADDR(sdl), interface->if_addrlen);
		}
		sdl->sdl_alen = lladdr_len;

		if (apply_type) {
			sdl->sdl_type = new_type;
		}
		IFA_UNLOCK(ifa);
	} else {
		error = ENXIO;
	}
	ifnet_lock_done(interface);
	ifnet_head_done();

	/* Generate a kernel event */
	if (error == 0) {
		dlil_post_msg(interface, KEV_DL_SUBCLASS,
			KEV_DL_LINK_ADDRESS_CHANGED, NULL, 0);
	}

	return (error);
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
ifnet_add_multicast(ifnet_t interface, const struct sockaddr *maddr,
    ifmultiaddr_t *ifmap)
{
	if (interface == NULL || maddr == NULL)
		return (EINVAL);

	/* Don't let users screw up protocols' entries. */
	if (maddr->sa_family != AF_UNSPEC && maddr->sa_family != AF_LINK)
		return (EINVAL);

	return (if_addmulti_anon(interface, maddr, ifmap));
}

errno_t
ifnet_remove_multicast(ifmultiaddr_t ifma)
{
	struct sockaddr *maddr;

	if (ifma == NULL)
		return (EINVAL);

	maddr = ifma->ifma_addr;
	/* Don't let users screw up protocols' entries. */
	if (maddr->sa_family != AF_UNSPEC && maddr->sa_family != AF_LINK)
		return (EINVAL);

	return (if_delmulti_anon(ifma->ifma_ifp, maddr));
}

errno_t
ifnet_get_multicast_list(ifnet_t ifp, ifmultiaddr_t **addresses)
{
	int count = 0;
	int cmax = 0;
	struct ifmultiaddr *addr;

	if (ifp == NULL || addresses == NULL)
		return (EINVAL);

	ifnet_lock_shared(ifp);
	LIST_FOREACH(addr, &ifp->if_multiaddrs, ifma_link) {
		cmax++;
	}

	MALLOC(*addresses, ifmultiaddr_t *, sizeof (ifmultiaddr_t) * (cmax + 1),
	    M_TEMP, M_NOWAIT);
	if (*addresses == NULL) {
		ifnet_lock_done(ifp);
		return (ENOMEM);
	}

	LIST_FOREACH(addr, &ifp->if_multiaddrs, ifma_link) {
		if (count + 1 > cmax)
			break;
		(*addresses)[count] = (ifmultiaddr_t)addr;
		ifmaddr_reference((*addresses)[count]);
		count++;
	}
	(*addresses)[cmax] = NULL;
	ifnet_lock_done(ifp);

	return (0);
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
ifnet_find_by_name(const char *ifname, ifnet_t *ifpp)
{
	struct ifnet *ifp;
	int	namelen;

	if (ifname == NULL)
		return (EINVAL);

	namelen = strlen(ifname);

	*ifpp = NULL;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		struct ifaddr *ifa;
		struct sockaddr_dl *ll_addr;

		ifa = ifnet_addrs[ifp->if_index - 1];
		if (ifa == NULL)
			continue;

		IFA_LOCK(ifa);
		ll_addr = (struct sockaddr_dl *)ifa->ifa_addr;

		if (namelen == ll_addr->sdl_nlen &&
		    !strncmp(ll_addr->sdl_data, ifname, ll_addr->sdl_nlen)) {
			IFA_UNLOCK(ifa);
			*ifpp = ifp;
			ifnet_reference(*ifpp);
			break;
		}
		IFA_UNLOCK(ifa);
	}
	ifnet_head_done();

	return ((ifp == NULL) ? ENXIO : 0);
}

errno_t
ifnet_list_get(ifnet_family_t family, ifnet_t **list, u_int32_t *count)
{
	return (ifnet_list_get_common(family, FALSE, list, count));
}

__private_extern__ errno_t
ifnet_list_get_all(ifnet_family_t family, ifnet_t **list, u_int32_t *count)
{
	return (ifnet_list_get_common(family, TRUE, list, count));
}

struct ifnet_list {
	SLIST_ENTRY(ifnet_list)	ifl_le;
	struct ifnet		*ifl_ifp;
};

static errno_t
ifnet_list_get_common(ifnet_family_t family, boolean_t get_all, ifnet_t **list,
    u_int32_t *count)
{
#pragma unused(get_all)
	SLIST_HEAD(, ifnet_list) ifl_head;
	struct ifnet_list *ifl, *ifl_tmp;
	struct ifnet *ifp;
	int cnt = 0;
	errno_t err = 0;

	SLIST_INIT(&ifl_head);

	if (list == NULL || count == NULL) {
		err = EINVAL;
		goto done;
	}
	*count = 0;
	*list = NULL;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		if (family == IFNET_FAMILY_ANY || ifp->if_family == family) {
			MALLOC(ifl, struct ifnet_list *, sizeof (*ifl),
			    M_TEMP, M_NOWAIT);
			if (ifl == NULL) {
				ifnet_head_done();
				err = ENOMEM;
				goto done;
			}
			ifl->ifl_ifp = ifp;
			ifnet_reference(ifp);
			SLIST_INSERT_HEAD(&ifl_head, ifl, ifl_le);
			++cnt;
		}
	}
	ifnet_head_done();

	if (cnt == 0) {
		err = ENXIO;
		goto done;
	}

	MALLOC(*list, ifnet_t *, sizeof (ifnet_t) * (cnt + 1),
	    M_TEMP, M_NOWAIT);
	if (*list == NULL) {
		err = ENOMEM;
		goto done;
	}
	bzero(*list, sizeof (ifnet_t) * (cnt + 1));
	*count = cnt;

done:
	SLIST_FOREACH_SAFE(ifl, &ifl_head, ifl_le, ifl_tmp) {
		SLIST_REMOVE(&ifl_head, ifl, ifnet_list, ifl_le);
		if (err == 0)
			(*list)[--cnt] = ifl->ifl_ifp;
		else
			ifnet_release(ifl->ifl_ifp);
		FREE(ifl, M_TEMP);
	}

	return (err);
}

void
ifnet_list_free(ifnet_t *interfaces)
{
	int i;

	if (interfaces == NULL)
		return;

	for (i = 0; interfaces[i]; i++)
		ifnet_release(interfaces[i]);

	FREE(interfaces, M_TEMP);
}

/****************************************************************************/
/* ifaddr_t accessors														*/
/****************************************************************************/

errno_t
ifaddr_reference(ifaddr_t ifa)
{
	if (ifa == NULL)
		return (EINVAL);

	IFA_ADDREF(ifa);
	return (0);
}

errno_t
ifaddr_release(ifaddr_t ifa)
{
	if (ifa == NULL)
		return (EINVAL);

	IFA_REMREF(ifa);
	return (0);
}

sa_family_t
ifaddr_address_family(ifaddr_t ifa)
{
	sa_family_t family = 0;

	if (ifa != NULL) {
		IFA_LOCK_SPIN(ifa);
		if (ifa->ifa_addr != NULL)
			family = ifa->ifa_addr->sa_family;
		IFA_UNLOCK(ifa);
	}
	return (family);
}

errno_t
ifaddr_address(ifaddr_t ifa, struct sockaddr *out_addr, u_int32_t addr_size)
{
	u_int32_t copylen;

	if (ifa == NULL || out_addr == NULL)
		return (EINVAL);

	IFA_LOCK_SPIN(ifa);
	if (ifa->ifa_addr == NULL) {
		IFA_UNLOCK(ifa);
		return (ENOTSUP);
	}

	copylen = (addr_size >= ifa->ifa_addr->sa_len) ?
	    ifa->ifa_addr->sa_len : addr_size;
	bcopy(ifa->ifa_addr, out_addr, copylen);

	if (ifa->ifa_addr->sa_len > addr_size) {
		IFA_UNLOCK(ifa);
		return (EMSGSIZE);
	}

	IFA_UNLOCK(ifa);
	return (0);
}

errno_t
ifaddr_dstaddress(ifaddr_t ifa, struct sockaddr *out_addr, u_int32_t addr_size)
{
	u_int32_t copylen;

	if (ifa == NULL || out_addr == NULL)
		return (EINVAL);

	IFA_LOCK_SPIN(ifa);
	if (ifa->ifa_dstaddr == NULL) {
		IFA_UNLOCK(ifa);
		return (ENOTSUP);
	}

	copylen = (addr_size >= ifa->ifa_dstaddr->sa_len) ?
	    ifa->ifa_dstaddr->sa_len : addr_size;
	bcopy(ifa->ifa_dstaddr, out_addr, copylen);

	if (ifa->ifa_dstaddr->sa_len > addr_size) {
		IFA_UNLOCK(ifa);
		return (EMSGSIZE);
	}

	IFA_UNLOCK(ifa);
	return (0);
}

errno_t
ifaddr_netmask(ifaddr_t ifa, struct sockaddr *out_addr, u_int32_t addr_size)
{
	u_int32_t copylen;

	if (ifa == NULL || out_addr == NULL)
		return (EINVAL);

	IFA_LOCK_SPIN(ifa);
	if (ifa->ifa_netmask == NULL) {
		IFA_UNLOCK(ifa);
		return (ENOTSUP);
	}

	copylen = addr_size >= ifa->ifa_netmask->sa_len ?
	    ifa->ifa_netmask->sa_len : addr_size;
	bcopy(ifa->ifa_netmask, out_addr, copylen);

	if (ifa->ifa_netmask->sa_len > addr_size) {
		IFA_UNLOCK(ifa);
		return (EMSGSIZE);
	}

	IFA_UNLOCK(ifa);
	return (0);
}

ifnet_t
ifaddr_ifnet(ifaddr_t ifa)
{
	struct ifnet *ifp;

	if (ifa == NULL)
		return (NULL);

	/* ifa_ifp is set once at creation time; it is never changed */
	ifp = ifa->ifa_ifp;

	return (ifp);
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
ifmaddr_reference(ifmultiaddr_t ifmaddr)
{
	if (ifmaddr == NULL)
		return (EINVAL);

	IFMA_ADDREF(ifmaddr);
	return (0);
}

errno_t
ifmaddr_release(ifmultiaddr_t ifmaddr)
{
	if (ifmaddr == NULL)
		return (EINVAL);

	IFMA_REMREF(ifmaddr);
	return (0);
}

errno_t
ifmaddr_address(ifmultiaddr_t ifma, struct sockaddr *out_addr,
    u_int32_t addr_size)
{
	u_int32_t copylen;

	if (ifma == NULL || out_addr == NULL)
		return (EINVAL);

	IFMA_LOCK(ifma);
	if (ifma->ifma_addr == NULL) {
		IFMA_UNLOCK(ifma);
		return (ENOTSUP);
	}

	copylen = (addr_size >= ifma->ifma_addr->sa_len ?
	    ifma->ifma_addr->sa_len : addr_size);
	bcopy(ifma->ifma_addr, out_addr, copylen);

	if (ifma->ifma_addr->sa_len > addr_size) {
		IFMA_UNLOCK(ifma);
		return (EMSGSIZE);
	}
	IFMA_UNLOCK(ifma);
	return (0);
}

errno_t
ifmaddr_lladdress(ifmultiaddr_t ifma, struct sockaddr *out_addr,
    u_int32_t addr_size)
{
	struct ifmultiaddr *ifma_ll;

	if (ifma == NULL || out_addr == NULL)
		return (EINVAL);
	if ((ifma_ll = ifma->ifma_ll) == NULL)
		return (ENOTSUP);

	return (ifmaddr_address(ifma_ll, out_addr, addr_size));
}

ifnet_t
ifmaddr_ifnet(ifmultiaddr_t ifma)
{
	return (ifma == NULL ? NULL : ifma->ifma_ifp);
}

/******************************************************************************/
/* interface cloner                                                           */
/******************************************************************************/

errno_t 
ifnet_clone_attach(struct ifnet_clone_params *cloner_params, if_clone_t *ifcloner)
{
	errno_t error = 0;
	struct if_clone *ifc = NULL;
	size_t namelen;
	
	if (cloner_params == NULL || ifcloner == NULL || cloner_params->ifc_name == NULL ||
		cloner_params->ifc_create == NULL || cloner_params->ifc_destroy == NULL ||
		(namelen = strlen(cloner_params->ifc_name)) >= IFNAMSIZ) {
		error = EINVAL;
		goto fail;
	}
	
	if (if_clone_lookup(cloner_params->ifc_name, NULL) != NULL) {
		printf("ifnet_clone_attach: already a cloner for %s\n", cloner_params->ifc_name);
		error = EEXIST;
		goto fail;
	}

	/* Make room for name string */
	ifc = _MALLOC(sizeof(struct if_clone) + IFNAMSIZ + 1, M_CLONE, M_WAITOK | M_ZERO);
	if (ifc == NULL) {
		printf("ifnet_clone_attach: _MALLOC failed\n");
		error = ENOBUFS;
		goto fail;
	}
	strlcpy((char *)(ifc + 1), cloner_params->ifc_name, IFNAMSIZ + 1);
	ifc->ifc_name = (char *)(ifc + 1);
	ifc->ifc_namelen = namelen;
	ifc->ifc_maxunit = IF_MAXUNIT;
	ifc->ifc_create = cloner_params->ifc_create;
	ifc->ifc_destroy = cloner_params->ifc_destroy;

	error = if_clone_attach(ifc);
	if (error != 0) {
		printf("ifnet_clone_attach: if_clone_attach failed %d\n", error);
		goto fail;
	}
	*ifcloner = ifc;
	
	return 0;
fail:
	if (ifc != NULL)
		FREE(ifc, M_CLONE);
	return error;	
}

errno_t 
ifnet_clone_detach(if_clone_t ifcloner)
{
	errno_t error = 0;
	struct if_clone *ifc = ifcloner;
	
	if (ifc == NULL || ifc->ifc_name == NULL)
		return EINVAL;
	
	if ((if_clone_lookup(ifc->ifc_name, NULL)) == NULL) {
		printf("ifnet_clone_attach: no cloner for %s\n", ifc->ifc_name);
		error = EINVAL;
		goto fail;
	}

	if_clone_detach(ifc);
	
	FREE(ifc, M_CLONE);

	return 0;
fail:
	return error;	
}



