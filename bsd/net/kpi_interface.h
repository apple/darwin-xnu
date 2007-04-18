/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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
/*!
	@header kpi_interface.h
	This header defines an API to interact with network interfaces in
	the kernel. The network interface KPI may be used to implement
	network interfaces or to attach protocols to existing interfaces.
 */

#ifndef __KPI_INTERFACE__
#define __KPI_INTERFACE__
#include <sys/kernel_types.h>

#ifndef _SA_FAMILY_T
#define _SA_FAMILY_T
typedef __uint8_t		sa_family_t;
#endif

struct timeval;
struct sockaddr;
struct sockaddr_dl;
struct kern_event_msg;
struct kev_msg;
struct ifnet_demux_desc;

/*!
	@enum Interface Families
	@abstract Constants defining interface families.
	@constant IFNET_FAMILY_ANY Match interface of any family type.
	@constant IFNET_FAMILY_LOOPBACK A software loopback interface.
	@constant IFNET_FAMILY_ETHERNET An Ethernet interface.
	@constant IFNET_FAMILY_SLIP A SLIP interface.
	@constant IFNET_FAMILY_TUN A tunnel interface.
	@constant IFNET_FAMILY_VLAN A virtual LAN interface.
	@constant IFNET_FAMILY_PPP A PPP interface.
	@constant IFNET_FAMILY_PVC A PVC interface.
	@constant IFNET_FAMILY_DISC A DISC interface.
	@constant IFNET_FAMILY_MDECAP A MDECAP interface.
	@constant IFNET_FAMILY_GIF A generic tunnel interface.
	@constant IFNET_FAMILY_FAITH A FAITH (IPv4/IPv6 translation) interface.
	@constant IFNET_FAMILY_STF A 6to4 interface.
	@constant IFNET_FAMILY_FIREWIRE An IEEE 1394 (firewire) interface.
	@constant IFNET_FAMILY_BOND A virtual bonded interface.
*/

enum {
		IFNET_FAMILY_ANY		= 0,
		IFNET_FAMILY_LOOPBACK	= 1,
		IFNET_FAMILY_ETHERNET	= 2,
		IFNET_FAMILY_SLIP		= 3,
		IFNET_FAMILY_TUN		= 4,
		IFNET_FAMILY_VLAN		= 5,
		IFNET_FAMILY_PPP		= 6,
		IFNET_FAMILY_PVC		= 7,
		IFNET_FAMILY_DISC		= 8,
		IFNET_FAMILY_MDECAP		= 9,
		IFNET_FAMILY_GIF		= 10,
		IFNET_FAMILY_FAITH		= 11,
		IFNET_FAMILY_STF		= 12,
		IFNET_FAMILY_FIREWIRE	= 13,
		IFNET_FAMILY_BOND		= 14
};
/*!
	@typedef ifnet_family_t
	@abstract Storage type for the interface family.
*/
typedef u_int32_t ifnet_family_t;

/*!
	@enum BPF tap mode
	@abstract Constants defining interface families.
	@constant BPF_MODE_DISABLED Disable bpf.
	@constant BPF_MODE_INPUT Enable input only.
	@constant BPF_MODE_OUTPUT Enable output only.
	@constant BPF_MODE_INPUT_OUTPUT Enable input and output.
*/

enum {
		BPF_MODE_DISABLED		= 0,
		BPF_MODE_INPUT			= 1,
		BPF_MODE_OUTPUT			= 2,
		BPF_MODE_INPUT_OUTPUT	= 3
};
/*!
	@typedef bpf_tap_mode
	@abstract Mode for tapping. BPF_MODE_DISABLED/BPF_MODE_INPUT_OUTPUT etc.
*/
typedef u_int32_t bpf_tap_mode;

/*!
	@typedef protocol_family_t
	@abstract Storage type for the protocol family.
*/
typedef u_int32_t protocol_family_t;

/*!
	@enum Interface Abilities
	@abstract Constants defining interface offload support.
	@constant IFNET_CSUM_IP Hardware will calculate IPv4 checksums.
	@constant IFNET_CSUM_TCP Hardware will calculate TCP checksums.
	@constant IFNET_CSUM_UDP Hardware will calculate UDP checksums.
	@constant IFNET_CSUM_FRAGMENT Hardware will checksum IP fragments.
	@constant IFNET_IP_FRAGMENT Hardware will fragment IP packets.
	@constant IFNET_VLAN_TAGGING Hardware will generate VLAN headers.
	@constant IFNET_VLAN_MTU Hardware supports VLAN MTU.
*/

enum {
		IFNET_CSUM_IP		= 0x00000001,
		IFNET_CSUM_TCP		= 0x00000002,
		IFNET_CSUM_UDP		= 0x00000004,
		IFNET_CSUM_FRAGMENT	= 0x00000008,
		IFNET_IP_FRAGMENT	= 0x00000010,
#ifdef KERNEL_PRIVATE
		IFNET_CSUM_SUM16	= 0x00001000,
#endif
		IFNET_VLAN_TAGGING	= 0x00010000,
		IFNET_VLAN_MTU		= 0x00020000,
};
/*!
	@typedef ifnet_offload_t
	@abstract Flags indicating the offload support of the interface.
*/
typedef u_int32_t ifnet_offload_t;

/*
 * Callbacks
 *
 * These are function pointers you supply to the kernel in the interface.
 */
/*!
	@typedef bpf_packet_func
	
	@discussion bpf_packet_func The bpf_packet_func is used to intercept
		inbound and outbound packets. The tap function will never free
		the mbuf. The tap function will only copy the mbuf in to various
		bpf file descriptors tapping this interface.
	@param interface The interface being sent or received on.
	@param data The packet to be transmitted or received.
	@result An errno value or zero upon success.
 */
/* Fast path - do not block or spend excessive amounts of time */
typedef errno_t (*bpf_packet_func)(ifnet_t interface, mbuf_t data);

/*!
	@typedef ifnet_output_func
	
	@discussion ifnet_output_func is used to transmit packets. The stack
		will pass fully formed packets, including frame header, to the
		ifnet_output function for an interface. The driver is
		responsible for freeing the mbuf.
	@param interface The interface being sent on.
	@param data The packet to be sent.
 */
/* Fast path - do not block or spend excessive amounts of time */
typedef errno_t (*ifnet_output_func)(ifnet_t interface, mbuf_t data);

/*!
	@typedef ifnet_ioctl_func
	@discussion ifnet_ioctl_func is used to communicate ioctls from the
		stack to the driver.
	@param interface The interface the ioctl is being sent to.
	@param proto_family The protocol family to handle the ioctl, may be
		zero for no protocol_family.
	@param cmd The ioctl command.
	@param data A pointer to any data related to the ioctl.
 */
typedef errno_t (*ifnet_ioctl_func)(ifnet_t interface, u_int32_t cmd, void *data);

/*!
	@typedef ifnet_set_bpf_tap
	@discussion ifnet_set_bpf_tap is used to set the bpf tap function to
		be called when packets are sent and/or received.
	@param interface The interface the bpf tap function is being set on.
	@param mode Sets the mode of the tap to either disabled, input,
		output, or input/output.
	@param callback A function pointer to be called when a packet is
		sent or received.
 */
typedef errno_t (*ifnet_set_bpf_tap)(ifnet_t interface, bpf_tap_mode mode,
				bpf_packet_func callback);

/*!
	@typedef ifnet_detached_func
	@discussion ifnet_detached_func is called an interface is detached
		from the list of interfaces. When ifnet_detach is called, it may
		not detach the interface immediately if protocols are attached.
		ifnet_detached_func is used to notify the interface that it has
		been detached from the networking stack. This is the last
		function that will be called on an interface. Until this
		function returns, you must not unload a kext supplying function
		pointers to this interface, even if ifnet_detacah has been
		called. Your detach function may be called during your call to
		ifnet_detach.
	@param interface The interface that has been detached.
		event.
 */
typedef void (*ifnet_detached_func)(ifnet_t interface);

/*!
	@typedef ifnet_demux_func
	@discussion ifnet_demux_func is called for each inbound packet to determine
		which protocol family the packet belongs to. This information is then
		used by the stack to determine which protocol to pass the packet to.
		This function may return protocol families for protocols that are
		not attached. If the protocol family has not been attached to the
		interface, the packet will be discarded.
	@param interface The interface the packet was received on.
	@param packet The mbuf containing the packet.
	@param frame_header A pointer to the frame header.
	@param protocol_family Upon return, the protocol family matching the
		packet should be stored here.
	@result
		If the result is zero, processing will continue normally.
		If the result is EJUSTRETURN, processing will stop but the packet will not be freed.
		If the result is anything else, the processing will stop and the packet will be freed.
 */
typedef errno_t (*ifnet_demux_func)(ifnet_t interface, mbuf_t packet,
									char *frame_header,
									protocol_family_t *protocol_family);

/*!
	@typedef ifnet_event_func
	@discussion ifnet_event_func is called when an event occurs on a
		specific interface.
	@param interface The interface the event occurred on.
	@param event_ptr Pointer to a kern_event structure describing the
		event.
 */
typedef void (*ifnet_event_func)(ifnet_t interface, const struct kev_msg *msg);

/*!
	@typedef ifnet_framer_func
	@discussion ifnet_framer_func is called for each outbound packet to
		give the interface an opportunity to prepend interface specific
		headers.
	@param interface The interface the packet is being sent on.
	@param packet Pointer to the mbuf containing the packet, caller may
		set this to a different mbuf upon return. This can happen if the
		frameout function needs to prepend another mbuf to the chain to
		have enough space for the header.
	@param dest The higher layer protocol destination (i.e. IP address).
	@param dest_linkaddr The link layer address as determined by the
		protocol's pre-output function.
	@param frame_type The frame type as determined by the protocol's
		pre-output function.
	@result
		If the result is zero, processing will continue normally.
		If the result is EJUSTRETURN, processing will stop but the packet will not be freed.
		If the result is anything else, the processing will stop and the packet will be freed.
 */
typedef errno_t (*ifnet_framer_func)(ifnet_t interface, mbuf_t *packet,
									 const struct sockaddr *dest,
									 const char *desk_linkaddr,
									 const char *frame_type);

/*!
	@typedef ifnet_add_proto_func
	@discussion if_add_proto_func is called by the stack when a protocol
		is attached to an interface. This gives the interface an
		opportunity to get a list of protocol description structures
		for demuxing packets to this protocol (demux descriptors).
	@param interface The interface the protocol will be attached to.
	@param protocol_family The family of the protocol being attached.
	@param demux_array An array of demux descriptors that describe
		the interface specific ways of identifying packets belonging
		to this protocol family.
	@param demux_count The number of demux descriptors in the array.
	@result
		If the result is zero, processing will continue normally.
		If the result is anything else, the add protocol will be aborted.
 */
typedef errno_t (*ifnet_add_proto_func)(ifnet_t interface,
										protocol_family_t protocol_family,
										const struct ifnet_demux_desc *demux_array,
										u_int32_t demux_count);

/*!
	@typedef if_del_proto_func
	@discussion if_del_proto_func is called by the stack when a protocol
		is being detached from an interface. This gives the interface an
		opportunity to free any storage related to this specific
		protocol being attached to this interface.
	@param interface The interface the protocol will be detached from.
	@param protocol_family The family of the protocol being detached.
	@result
		If the result is zero, processing will continue normally.
		If the result is anything else, the detach will continue
			and the error will be returned to the caller.
 */
typedef errno_t (*ifnet_del_proto_func)(ifnet_t interface,
										protocol_family_t protocol_family);

/*!
	@typedef ifnet_check_multi
	@discussion ifnet_check_multi is called for each multicast address
		added to an interface. This gives the interface an opportunity
		to reject invalid multicast addresses before they are attached
		to the interface.
		
		To prevent an address from being added to your multicast list,
		return EADDRNOTAVAIL. If you don't know how to parse/translate
		the address, return EOPNOTSUPP.
	@param The interface.
	@param mcast The multicast address.
	@result
		Zero upon success, EADDRNOTAVAIL on invalid multicast,
		EOPNOTSUPP for addresses the interface does not understand.
 */
typedef errno_t (*ifnet_check_multi)(ifnet_t interface,
									 const struct sockaddr* mcast);

/*!
	@typedef proto_media_input
	@discussion proto_media_input is called for all inbound packets for
		a specific protocol on a specific interface. This function is
		registered on an interface using ifnet_attach_protocol.
	@param ifp The interface the packet was received on.
	@param protocol_family The protocol of the packet received.
	@param packet The packet being input.
	@param header The frame header.
	@result
		If the result is zero, the caller will assume the packet was passed
		to the protocol.
		If the result is non-zero and not EJUSTRETURN, the caller will free
		the packet.
 */
typedef errno_t (*proto_media_input)(ifnet_t ifp, protocol_family_t protocol,
									 mbuf_t packet, char* header);

/*!
	@typedef proto_media_preout
	@discussion proto_media_preout is called just before the packet
		is transmitted. This gives the proto_media_preout function an
		opportunity to specify the media specific frame type and
		destination.
	@param ifp The interface the packet will be sent on.
	@param protocol_family The protocol of the packet being sent
		(PF_INET/etc...).
	@param packet The packet being sent.
	@param dest The protocol level destination address.
	@param route A pointer to the routing structure for the packet.
	@param frame_type The media specific frame type.
	@param link_layer_dest The media specific destination.
	@result
		If the result is zero, processing will continue normally. If the
		result is non-zero, processing will stop. If the result is
		non-zero and not EJUSTRETURN, the packet will be freed by the
		caller.
 */
typedef errno_t (*proto_media_preout)(ifnet_t ifp, protocol_family_t protocol,
									  mbuf_t *packet, const struct sockaddr *dest,
									  void *route, char *frame_type, char *link_layer_dest);

/*!
	@typedef proto_media_event
	@discussion proto_media_event is called to notify this layer of
		interface specific events.
	@param ifp The interface.
	@param protocol_family The protocol family.
	@param kev_msg The event.
 */
typedef void (*proto_media_event)(ifnet_t ifp, protocol_family_t protocol,
								  const struct kev_msg *event);

/*!
	@typedef proto_media_ioctl
	@discussion proto_media_event allows this layer to handle ioctls.
		When an ioctl is handled, it is passed to the interface filters,
		protocol filters, protocol, and interface. If you do not support
		this ioctl, return EOPNOTSUPP. If you successfully handle the
		ioctl, return zero. If you return any error other than
		EOPNOTSUPP, other parts of the stack may not get an opportunity
		to process the ioctl. If you return EJUSTRETURN, processing will
		stop and a result of zero will be returned to the caller.
	@param ifp The interface.
	@param protocol_family The protocol family.
	@param command The ioctl command.
	@param argument The argument to the ioctl.
	@result
		See the discussion.
 */
typedef errno_t (*proto_media_ioctl)(ifnet_t ifp, protocol_family_t protocol,
									 u_int32_t command, void* argument);

/*!
	@typedef proto_media_detached
	@discussion proto_media_detached notifies you that your protocol
		has been detached.
	@param ifp The interface.
	@param protocol_family The protocol family.
	@result
		See the discussion.
 */
typedef errno_t (*proto_media_detached)(ifnet_t ifp, protocol_family_t protocol);


/*!
	@typedef proto_media_resolve_multi
	@discussion proto_media_resolve_multi is called to resolve a
		protocol layer mulitcast address to a link layer multicast
		address.
	@param ifp The interface.
	@param proto_addr The protocol address.
	@param out_ll A sockaddr_dl to copy the link layer multicast in to.
	@param ll_len The length of data allocated for out_ll.
	@result Return zero on success or an errno error value on failure.
 */
typedef errno_t (*proto_media_resolve_multi)(ifnet_t ifp,
									 const struct sockaddr *proto_addr,
									 struct sockaddr_dl *out_ll, size_t ll_len);

/*!
	@typedef proto_media_send_arp
	@discussion proto_media_send_arp is called by the stack to generate
		an ARP packet. This field is currently only used with IP. This
		function should inspect the parameters and transmit an arp
		packet using the information passed in.
	@param ifp The interface the arp packet should be sent on.
	@param protocol_family The protocol family of the addresses
		(PF_INET).
	@param arpop The arp operation (usually ARPOP_REQUEST or
		ARPOP_REPLY).
	@param sender_hw The value to use for the sender hardware
		address field. If this is NULL, use the hardware address
		of the interface.
	@param sender_proto The value to use for the sender protocol
		address field. This will not be NULL.
	@param target_hw The value to use for the target hardware address.
		If this is NULL, the target hardware address in the ARP packet
		should be NULL and the link-layer destination for the back
		should be a broadcast. If this is not NULL, this value should be
		used for both the link-layer destination and the target hardware
		address.
	@param target_proto The target protocol address. This will not be
		NULL.
	@result Return zero on success or an errno error value on failure.
 */
typedef errno_t (*proto_media_send_arp)(ifnet_t ifp,
					u_short arpop,
					const struct sockaddr_dl* sender_hw,
					const struct sockaddr* sender_proto,
					const struct sockaddr_dl* target_hw,
					const struct sockaddr* target_proto);

/*!
	@struct ifnet_stat_increment_param
	@discussion This structure is used increment the counters on a
		network interface.
	@field packets_in The number of packets received.
	@field bytes_in The number of bytes received.
	@field errors_in The number of receive errors.
	@field packets_out The number of packets transmitted.
	@field bytes_out The number of bytes transmitted.
	@field errors_out The number of transmission errors.
	@field collisions The number of collisions seen by this interface.
	@field dropped The number of packets dropped.
*/

struct ifnet_stat_increment_param {
	u_int32_t				packets_in;
	u_int32_t				bytes_in;
	u_int32_t				errors_in;
	
	u_int32_t				packets_out;
	u_int32_t				bytes_out;
	u_int32_t				errors_out;
	
	u_int32_t				collisions;
	u_int32_t				dropped;
};

/*!
	@struct ifnet_init_params
	@discussion This structure is used to define various properties of
		the interface when calling ifnet_init. A copy of these values
		will be stored in the ifnet and can not be modified while the
		interface is attached.
	@field uniqueid An identifier unique to this instance of the
		interface.
	@field uniqueid_len The length, in bytes, of the uniqueid.
	@field name The interface name (i.e. en).
	@field unit The interface unit number (en0's unit number is 0).
	@field family The interface family.
	@field type The interface type (see sys/if_types.h). Must be less
		than 256. For new types, use IFT_OTHER.
	@field output The output function for the interface. Every packet the
		stack attempts to send through this interface will go out through
		this function.
	@field demux The function used to determine the protocol family of an
		incoming packet.
	@field add_proto The function used to attach a protocol to this interface.
	@field del_proto The function used to remove a protocol from this interface.
	@field framer The function used to frame outbound packets, may be NULL.
	@field softc Driver specific storage. This value can be retrieved from the
		ifnet using the ifnet_softc function.
	@field ioctl The function used to handle ioctls.
	@field set_bpf_tap The function used to set the bpf_tap function.
	@field detach The function called to let the driver know the interface has been detached.
	@field event The function to notify the interface of various interface specific kernel events.
	@field broadcast_addr The link-layer broadcast address for this interface.
	@field broadcast_len The length of the link-layer broadcast address.
*/

struct ifnet_init_params {
	/* used to match recycled interface */
	const void*				uniqueid;		/* optional */
	u_int32_t				uniqueid_len;	/* optional */
	
	/* used to fill out initial values for interface */
	const char*				name;			/* required */
	u_int32_t				unit;			/* required */
	ifnet_family_t 			family;			/* required */
	u_int32_t				type;			/* required */
	ifnet_output_func		output;			/* required */
	ifnet_demux_func		demux;			/* required  */
	ifnet_add_proto_func	add_proto;		/* required  */
	ifnet_del_proto_func	del_proto;		/* required  */
	ifnet_check_multi		check_multi;	/* required for non point-to-point interfaces */
	ifnet_framer_func		framer;			/* optional */
	void*					softc;			/* optional */
	ifnet_ioctl_func		ioctl;			/* optional */
	ifnet_set_bpf_tap		set_bpf_tap;	/* optional */
	ifnet_detached_func		detach;			/* optional */
	ifnet_event_func		event;			/* optional */
	const void				*broadcast_addr;/* required for non point-to-point interfaces */
	u_int32_t				broadcast_len;	/* required for non point-to-point interfaces */
};

/*!
	@struct ifnet_stats_param
	@discussion This structure is used get and set the interface
		statistics.
	@field packets_in The number of packets received.
	@field bytes_in The number of bytes received.
	@field errors_in The number of receive errors.
	@field packets_out The number of packets transmitted.
	@field bytes_out The number of bytes transmitted.
	@field errors_out The number of transmission errors.
	@field collisions The number of collisions seen by this interface.
	@field dropped The number of packets dropped.
*/

struct ifnet_stats_param {
	u_int64_t	packets_in;
	u_int64_t	bytes_in;
	u_int64_t	multicasts_in;
	u_int64_t	errors_in;
	
	u_int64_t	packets_out;
	u_int64_t	bytes_out;
	u_int64_t	multicasts_out;
	u_int64_t	errors_out;
	
	u_int64_t	collisions;
	u_int64_t	dropped;
	u_int64_t	no_protocol;
};

/*!
	@struct ifnet_demux_desc
	@discussion This structure is to identify packets that belong to a
		specific protocol. The types supported are interface specific.
		Ethernet supports ETHER_DESC_ETYPE2, ETHER_DESC_SAP, and
		ETHER_DESC_SNAP. The type defines the offset in the packet where
		the data will be matched as well as context. For example, if
		ETHER_DESC_SNAP is specified, the only valid datalen is 5 and
		only in the 5 bytes will only be matched when the packet header
		indicates that the packet is a SNAP packet.
	@field type The type of identifier data (i.e. ETHER_DESC_ETYPE2)
	@field data A pointer to an entry of type (i.e. pointer to 0x0800).
	@field datalen The number of bytes of data used to describe the
		packet.
*/

struct ifnet_demux_desc {
	u_int32_t	type;
	void*		data;
	u_int32_t	datalen;
};

/*!
	@struct ifnet_attach_proto_param
	@discussion This structure is used to attach a protocol to an
		interface. This structure provides the various functions for
		handling operations related to the protocol on the interface as
		well as information for how to demux packets for this protocol.
	@field demux_array An array of ifnet_demux_desc structures
		describing the protocol.
	@field demux_count The number of entries in the demux_array array.
	@field input The function to be called for inbound packets.
	@field pre_output The function to be called for outbound packets.
	@field event The function to be called for interface events.
	@field ioctl The function to be called for ioctls.
	@field detached The function to be called for handling the detach.
*/
#ifdef KERNEL_PRIVATE
#define demux_list demux_array
#endif /* KERNEL_PRIVATE */

struct ifnet_attach_proto_param {
	struct ifnet_demux_desc	*demux_array;	/* interface may/may not require */
	u_int32_t				demux_count;	/* interface may/may not require */
	
	proto_media_input			input;		/* required */
	proto_media_preout			pre_output;	/* required */
	proto_media_event			event;		/* optional */
	proto_media_ioctl			ioctl;		/* optional */
	proto_media_detached		detached;	/* optional */
	proto_media_resolve_multi	resolve;	/* optional */
	proto_media_send_arp		send_arp;	/* optional */
};

__BEGIN_DECLS

/*
 * Ifnet creation and reference counting
 */

/*!
	@function ifnet_allocate
	@discussion Allocate an ifnet_t with an initial refcount of 1. Many
		parts of the stack do not properly refcount the ifnet_t. In
		order to avoid freeing the ifnet_t while some parts of the stack
		may contain a reference to it, the ifnet_ts are only recycled,
		never freed. A unique id is used to try and recycle the same
		ifnet_t when allocating an interface. For example, for an
		ethernet interface, the hardware address of the ethernet card is
		usually used for the uniqueid. If a PC Card is removed and
		inserted again, if the ethernet address of the PC card is used,
		the same ifnet_t will be used for the card the second time it is
		inserted. In the future, when the ifnet_t is correctly
		refcounted by all of the stack, the interfaces may be freed and
		the unique ids ignored.
	@param init The initial values for the interface. These values can
		not be changed after the interface has been allocated.
	@param interface The interface allocated upon success.
	@result May return ENOMEM if there is insufficient memory or EEXIST
		if an interface with the same uniqueid and family has already
		been allocated and is in use.
 */
errno_t ifnet_allocate(const struct ifnet_init_params *init, ifnet_t *interface);

/*!
	@function ifnet_reference
	@discussion Increment the reference count of the ifnet to assure
		that it will not go away. The interface must already have at
		least one reference.
	@param interface The interface to increment the reference count of.
	@result May return EINVAL if the interface is not valid.
 */
errno_t ifnet_reference(ifnet_t interface);

/*!
	@function ifnet_release
	@discussion Release a reference of the ifnet, this may trigger a
		free if the reference count reaches 0.
	@param interface The interface to decrement the reference count of
		and possibly free.
	@result May return EINVAL if the interface is not valid.
 */
errno_t ifnet_release(ifnet_t interface);

/*!
	@function ifnet_attach
	@discussion Attaches an interface to the global interface list. The
		interface must be setup properly before calling attach. The
		stack will take a reference on the interface and hold it until
		ifnet_detach is called.
		
		This function is intended to be called by the driver. A kext
		must not call this function on an interface the kext does not
		own.
	@param interface The interface to attach.
	@param ll_addr The link layer address of the interface. This is used
		to fill out the first ifaddr in the list of addresses for the
		interface. This parameter is not required for interfaces such as
		PPP that have no link-layer address.
	@result Will return an error if there is anything wrong with the
		interface.
 */
errno_t ifnet_attach(ifnet_t interface, const struct sockaddr_dl *ll_addr);

/*!
	@function ifnet_detach
	@discussion Detaches the interface.
		
		Call this to indicate this interface is no longer valid (i.e. PC
		Card was removed). This function will begin the process of
		removing knowledge of this interface from the stack.
		
		The function will return before the interface is detached. The
		functions you supplied in to the interface may continue to be
		called. When the detach has been completed, your detached
		function will be called. Your kext must not unload until the
		detached function has been called. The interface will be
		properly freed when the reference count reaches zero.
		
		An interface may not be attached again. You must call
		ifnet_allocate to create a new interface to attach.
		
		This function is intended to be called by the driver. A kext
		must not call this function on an interface the kext does not
		own.
	@param interface The interface to detach.
	@result 0 on success, otherwise errno error.
 */
errno_t ifnet_detach(ifnet_t interface);

/*
 * Interface manipulation.
 */

/*!
	@function ifnet_softc
	@discussion Returns the driver's private storage on the interface.
	@param interface Interface to retrieve the storage from.
	@result Driver's private storage.
 */
void* ifnet_softc(ifnet_t interface);

/*!
	@function ifnet_name
	@discussion Returns a pointer to the name of the interface.
	@param interface Interface to retrieve the name from.
	@result Pointer to the name.
 */
const char* ifnet_name(ifnet_t interface);

/*!
	@function ifnet_family
	@discussion Returns the family of the interface.
	@param interface Interface to retrieve the unit number from.
	@result Unit number.
 */
ifnet_family_t ifnet_family(ifnet_t interface);

/*!
	@function ifnet_unit
	@discussion Returns the unit number of the interface.
	@param interface Interface to retrieve the unit number from.
	@result Unit number.
 */
u_int32_t ifnet_unit(ifnet_t interface);

/*!
	@function ifnet_index
	@discussion Returns the index of the interface. This index value
		will match the index you would find in a sockaddr_dl or using
		if_nametoindex or if_indextoname in user space. The value of the
		interface index is undefined for an interface that is not
		currently attached.
	@param interface Interface to retrieve the index of.
	@result Index.
 */
u_int32_t ifnet_index(ifnet_t interface);

/*!
	@function ifnet_set_flags
	@discussion Sets the interface flags to match new_flags.
	@discussion Sets the interface flags to new_flags. This function
		lets you specify which flags you want to change using the mask.
		The kernel will effectively take the lock, then set the
		interface's flags to (if_flags & ~mask) | (new_flags & mask).
	@param interface Interface to set the flags on.
	@param new_flags The new set of flags that should be set. These
		flags are defined in net/if.h
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_set_flags(ifnet_t interface, u_int16_t new_flags, u_int16_t mask);

/*!
	@function ifnet_flags
	@discussion Returns the interface flags that are set.
	@param interface Interface to retrieve the flags from.
	@result Flags. These flags are defined in net/if.h
 */
u_int16_t ifnet_flags(ifnet_t interface);


#ifdef KERNEL_PRIVATE
/*!
	@function ifnet_set_eflags
	@discussion Sets the extended interface flags to new_flags. This
		function lets you specify which flags you want to change using
		the mask. The kernel will effectively take the lock, then set
		the interface's extended flags to (if_eflags & ~mask) |
		(new_flags & mask).
	@param interface The interface.
	@param new_flags The new set of flags that should be set. These
		flags are defined in net/if.h
	@param mask The mask of flags to be modified.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_set_eflags(ifnet_t interface, u_int32_t new_flags, u_int32_t mask);

/*!
	@function ifnet_eflags
	@discussion Returns the extended interface flags that are set.
	@param interface Interface to retrieve the flags from.
	@result Extended flags. These flags are defined in net/if.h
 */
u_int32_t ifnet_eflags(ifnet_t interface);
#endif

/*!
	@function ifnet_set_offload
	@discussion Sets a bitfield to indicate special hardware offload
		support provided by the interface such as hardware checksums and
		VLAN. This replaces the if_hwassist flags field. Any flags
		unrecognized by the stack will not be set.
	@param interface The interface.
	@param offload The new set of flags indicating which offload options
		the device supports.
	@param mask The mask of flags to be modified.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_set_offload(ifnet_t interface, ifnet_offload_t offload);

/*!
	@function ifnet_offload
	@discussion Returns flags indicating which operations can be
		offloaded to the interface.
	@param interface Interface to retrieve the offload from.
	@result Abilities flags, see ifnet_offload_t.
 */
ifnet_offload_t ifnet_offload(ifnet_t interface);

/*!
	@function ifnet_set_link_mib_data
	@discussion Sets the mib link data. The ifnet_t will store the
		pointer you supply and copy mibLen bytes from the pointer
		whenever the sysctl for getting interface specific MIB data is
		used. Since the ifnet_t stores a pointer to your data instead of
		a copy, you may update the data at the address at any time.
		
		This function is intended to be called by the driver. A kext
		must not call this function on an interface the kext does not
		own.
	@param interface Interface to set the unit number of.
	@param mibData A pointer to the data.
	@param mibLen Length of data pointed to.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_set_link_mib_data(ifnet_t interface, void *mibData, u_int32_t mibLen);

/*!
	@function ifnet_get_link_mib_data
	@discussion Copies the link MIB data in to mibData, up to mibLen
		bytes. Returns error if the buffer is too small to hold all of
		the MIB data.
	@param interface The interface.
	@param mibData A pointer to space for the mibData to be copied in
		to.
	@param mibLen When calling, this should be the size of the buffer
		passed in mibData. Upon return, this will be the size of data
		copied in to mibData.
	@result Returns an error if the buffer size is too small or there is
		no data.
 */
errno_t ifnet_get_link_mib_data(ifnet_t interface, void *mibData, u_int32_t *mibLen);

/*!
	@function ifnet_get_link_mib_data_length
	@discussion Retrieve the size of the mib data.
	@param interface The interface.
	@result Returns the number of bytes of mib data associated with the
		interface.
 */
u_int32_t ifnet_get_link_mib_data_length(ifnet_t interface);

/*!
	@function ifnet_attach_protocol
	@discussion Attaches a protocol to an interface.
	@param interface The interface.
	@param protocol_family The protocol family being attached
		(PF_INET/PF_APPLETALK/etc...).
	@param proto_details Details of the protocol being attached.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_attach_protocol(ifnet_t interface, protocol_family_t protocol_family,
			const struct ifnet_attach_proto_param *proto_details);

/*!
	@function ifnet_detach_protocol
	@discussion Detaches a protocol from an interface.
	@param interface The interface.
	@param protocol_family The protocol family of the protocol to
		detach.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_detach_protocol(ifnet_t interface, protocol_family_t protocol_family);

/*!
	@function ifnet_output
	@discussion Handles an outbound packet on the interface by calling
		any filters, a protocol preoutput function, the interface framer
		function, and finally the interface's output function. The
		protocol_family will be used to apply protocol filters and
		determine which preoutput function to call. The route and dest
		parameters will be passed to the preoutput function defined for
		the attachment of the specified protocol to the specified
		interface. ifnet_output will free the mbuf chain in the event of
		an error.
	@param interface The interface.
	@param protocol_family The family of the protocol generating this
		packet (i.e. AF_INET).
	@param packet The packet to be transmitted.
	@param route A pointer to a routing structure for this packet. The
		preoutput function determines whether this value may be NULL or
		not.
	@param dest The destination address of protocol_family type. This
		will be passed to the preoutput function. If the preoutput
		function does not require this value, you may pass NULL.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_output(ifnet_t interface, protocol_family_t protocol_family, mbuf_t packet,
					void* route, const struct sockaddr *dest);

/*!
	@function ifnet_output_raw
	@discussion Handles and outbond raw packet on the interface by
		calling any filters followed by the interface's output function.
		protocol_family may be zero. If the packet is from a specific
		protocol the protocol_family will be used to apply protocol
		filters. All interface filters will be applied to the outgoing
		packet. Processing, such as calling the protocol preoutput and
		interface framer functions will be bypassed. The packet will
		pass through the filters and be sent on the interface as is.
		ifnet_output_raw will free the packet chain in the event of an
		error.
	@param interface The interface.
	@param protocol_family The family of the protocol generating this
		packet (i.e. AF_INET).
	@param packet The fully formed packet to be transmitted.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_output_raw(ifnet_t interface, protocol_family_t protocol_family, mbuf_t packet);

/*!
	@function ifnet_input
	@discussion Inputs packets from the interface. The interface's demux
		will be called to determine the protocol. Once the protocol is
		determined, the interface filters and protocol filters will be
		called. From there, the packet will be passed to the registered
		protocol. If there is an error, the mbuf chain will be freed.
	@param interface The interface.
	@param first_packet The first packet in a chain of packets.
	@param stats Counts to be integrated in to the stats. The interface
		statistics will be incremented by the amounts specified in
		stats. This parameter may be NULL.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_input(ifnet_t interface, mbuf_t first_packet,
					const struct ifnet_stat_increment_param *stats);

/*!
	@function ifnet_ioctl
	@discussion Calls the interface's ioctl function with the parameters
		passed.
	@param interface The interface.
	@param protocol The protocol family of the protocol to send the
		ioctl to (may be zero). Some ioctls apply to a protocol while
		other ioctls apply to just an interface.
	@param ioctl_code The ioctl to perform.
	@param ioctl_arg Any parameters to the ioctl.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_ioctl(ifnet_t interface, protocol_family_t protocol,
					u_int32_t ioctl_code, void *ioctl_arg);

/*!
	@function ifnet_event
	@discussion Calls the interface's event function.
	@param interface The interface.
	@param event_ptr Pointer to an kern_event structure describing the
		event.
	@result 0 on success otherwise the errno error.
 */
errno_t	ifnet_event(ifnet_t interface, struct kern_event_msg* event_ptr);

/*!
	@function ifnet_set_mtu
	@discussion Sets the value of the MTU in the interface structure.
		Calling this function will not notify the driver that the MTU
		should be changed. Use the appropriate ioctl.
		
		This function is intended to be called by the driver. A kext
		must not call this function on an interface the kext does not
		own.
	@param interface The interface.
	@param mtu The new MTU.
	@result 0 on success otherwise the errno error.
 */
errno_t	ifnet_set_mtu(ifnet_t interface, u_int32_t mtu);

/*!
	@function ifnet_mtu
	@param interface The interface.
	@result The MTU.
 */
u_int32_t	ifnet_mtu(ifnet_t interface);

/*!
	@function ifnet_type
	@param interface The interface.
	@result The type. See net/if_types.h.
 */
u_int8_t	ifnet_type(ifnet_t interface);

/*!
	@function ifnet_set_addrlen
	@discussion
		This function is intended to be called by the driver. A kext
		must not call this function on an interface the kext does not
		own.
	@param interface The interface.
	@param addrlen The new address length.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_set_addrlen(ifnet_t interface, u_int8_t addrlen);

/*!
	@function ifnet_addrlen
	@param interface The interface.
	@result The address length.
 */
u_int8_t	ifnet_addrlen(ifnet_t interface);

/*!
	@function ifnet_set_hdrlen
	@discussion
		This function is intended to be called by the driver. A kext
		must not call this function on an interface the kext does not
		own.
	@param interface The interface.
	@param hdrlen The new header length.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_set_hdrlen(ifnet_t interface, u_int8_t hdrlen);

/*!
	@function ifnet_hdrlen
	@param interface The interface.
	@result The header length.
 */
u_int8_t	ifnet_hdrlen(ifnet_t interface);

/*!
	@function ifnet_set_metric
	@discussion
		This function is intended to be called by the driver. A kext
		must not call this function on an interface the kext does not
		own.
	@param interface The interface.
	@param metric The new metric.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_set_metric(ifnet_t interface, u_int32_t metric);

/*!
	@function ifnet_metric
	@param interface The interface.
	@result The metric.
 */
u_int32_t	ifnet_metric(ifnet_t interface);

/*!
	@function ifnet_set_baudrate
	@discussion
		This function is intended to be called by the driver. A kext
		must not call this function on an interface the kext does not
		own.
	@param interface The interface.
	@param baudrate The new baudrate.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_set_baudrate(ifnet_t interface, u_int64_t baudrate);

/*!
	@function ifnet_baudrate
	@param interface The interface.
	@result The baudrate.
 */
u_int64_t	ifnet_baudrate(ifnet_t interface);

/*!
	@function ifnet_stat_increment
	@discussion
		This function is intended to be called by the driver. A kext
		must not call this function on an interface the kext does not
		own.
	@param interface The interface.
	@param counts A pointer to a structure containing the amount to
		increment each counter by. Any counts not appearing in the
		ifnet_counter_increment structure are handled in the stack.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_stat_increment(ifnet_t interface,
				const struct ifnet_stat_increment_param *counts);

/*!
	@function ifnet_stat_increment_in
	@discussion
		This function is intended to be called by the driver. This
		function allows a driver to update the inbound interface counts.
		The most efficient time to update these counts is when calling
		ifnet_input.
		
		A lock protects the counts, this makes the increment functions
		expensive. The increment function will update the lastchanged
		value.
	@param interface The interface.
	@param packets_in The number of additional packets received.
	@param bytes_in The number of additional bytes received.
	@param errors_in The number of additional receive errors.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_stat_increment_in(ifnet_t interface,
				u_int32_t packets_in, u_int32_t bytes_in,
				u_int32_t errors_in);

/*!
	@function ifnet_stat_increment_out
	@discussion
		This function is intended to be called by the driver. This
		function allows a driver to update the outbound interface counts.
		
		A lock protects the counts, this makes the increment functions
		expensive. The increment function will update the lastchanged
		value.
	@param interface The interface.
	@param packets_out The number of additional packets sent.
	@param bytes_out The number of additional bytes sent.
	@param errors_out The number of additional send errors.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_stat_increment_out(ifnet_t interface,
				u_int32_t packets_out, u_int32_t bytes_out,
				u_int32_t errors_out);

/*!
	@function ifnet_set_stat
	@discussion
		This function is intended to be called by the driver. A kext
		must not call this function on an interface the kext does not
		own.
		
		The one exception would be the case where a kext wants to zero
		all of the counters.
	@param interface The interface.
	@param counts The new stats values.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_set_stat(ifnet_t interface,
				const struct ifnet_stats_param *stats);

/*!
	@function ifnet_stat
	@param interface The interface.
	@param out_stats Storage for the values.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_stat(ifnet_t interface,
				struct ifnet_stats_param *out_stats);

/*!
	@function ifnet_set_promiscuous
	@discussion Enable or disable promiscuous mode on the interface. The
		interface keeps an internal count of the number of times
		promiscuous mode has been enabled. Promiscuous mode is only
		disabled when this count reaches zero. Be sure to disable
		promiscuous mode only once for every time you enable it.
	@param interface The interface to toggle promiscuous mode on.
	@param on If set, the number of promicuous on requests will be
		incremented. If this is the first requrest, promiscuous mode
		will be enabled. If this is not set, the number of promiscous
		clients will be decremented. If this causes the number to reach
		zero, promiscuous mode will be disabled.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_set_promiscuous(ifnet_t interface, int on);

/*!
	@function ifnet_touch_lastchange
	@discussion Updates the lastchange value to now.
	@param interface The interface.
	@result 0 on success otherwise the errno error.
 */
errno_t		ifnet_touch_lastchange(ifnet_t interface);

/*!
	@function ifnet_lastchange
	@param interface The interface.
	@param last_change A timeval struct to copy the last time changed in
		to.
 */
errno_t		ifnet_lastchange(ifnet_t interface, struct timeval *last_change);

/*!
	@function ifnet_get_address_list
	@discussion Get a list of addresses on the interface. Passing NULL
		for the interface will return a list of all addresses. The
		addresses will have their reference count bumped so they will
		not go away. Calling ifnet_free_address_list will decrement the
		refcount and free the array. If you wish to hold on to a
		reference to an ifaddr_t, be sure to bump the reference count
		before calling ifnet_free_address_list.
	@param interface The interface.
	@param addresses A pointer to a NULL terminated array of ifaddr_ts.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_get_address_list(ifnet_t interface, ifaddr_t **addresses);

/*!
	@function ifnet_get_address_list_family
	@discussion Get a list of addresses on the interface. Passing NULL
		for the interface will return a list of all addresses. The
		addresses will have their reference count bumped so they will
		not go away. Calling ifnet_free_address_list will decrement the
		refcount and free the array. If you wish to hold on to a
		reference to an ifaddr_t, be sure to bump the reference count
		before calling ifnet_free_address_list. Unlike
		ifnet_get_address_list, this function lets the caller specify
		the address family to get a list of only a specific address type.
	@param interface The interface.
	@param addresses A pointer to a NULL terminated array of ifaddr_ts.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_get_address_list_family(ifnet_t interface, ifaddr_t **addresses, sa_family_t family);

/*!
	@function ifnet_free_address_list
	@discussion Free a list of addresses returned from
		ifnet_get_address_list. Decrements the refcounts and frees the
		memory used for the array of references.
	@param addresses An array of ifaddr_ts.
 */
void ifnet_free_address_list(ifaddr_t *addresses);

/*!
	@function ifnet_set_lladdr
	@discussion Sets the link-layer address for this interface.
	@param interface The interface the link layer address is being
		changed on.
	@param lladdr A pointer to the raw link layer address (pointer to
		the 6 byte ethernet address for ethernet).
	@param lladdr_len The length, in bytes, of the link layer address.
 */
errno_t ifnet_set_lladdr(ifnet_t interface, const void* lladdr, size_t lladdr_len);

/*!
	@function ifnet_lladdr_copy_bytes
	@discussion Copies the bytes of the link-layer address in to the
		specified buffer.
	@param interface The interface to copy the link-layer address from.
	@param lladdr The buffer to copy the link-layer address in to.
	@param length The length of the buffer. This value must match the
		length of the link-layer address.
 */
errno_t ifnet_lladdr_copy_bytes(ifnet_t interface, void* lladdr, size_t length);

#ifdef KERNEL_PRIVATE
/*!
	@function ifnet_lladdr
	@discussion Returns a pointer to the link-layer address.
	@param interface The interface the link-layer address is on.
 */
void* ifnet_lladdr(ifnet_t interface);
#endif KERNEL_PRIVATE

/*!
	@function ifnet_llbroadcast_copy_bytes
	@discussion Retrieves the link-layer broadcast address for this
		interface.
	@param interface The interface.
	@param addr A buffer to copy the broadcast address in to.
	@param bufferlen The length of the buffer at addr.
	@param addr_len On return, the length of the broadcast address.
	@param lladdr_len The length, in bytes, of the link layer address.
 */
errno_t ifnet_llbroadcast_copy_bytes(ifnet_t interface, void* addr,
									 size_t bufferlen, size_t* addr_len);

#ifdef KERNEL_PRIVATE
/*!
	@function ifnet_set_lladdr_and_type
	@discussion Sets the link-layer address as well as the type field in
		the sockaddr_dl. Support for setting the type was added for vlan
		and bond interfaces.
	@param interface The interface the link layer address is being
		changed on.
	@param lladdr A pointer to the raw link layer address (pointer to
		the 6 byte ethernet address for ethernet).
	@param lladdr_len The length, in bytes, of the link layer address.
	@param type The link-layer address type.
 */
errno_t ifnet_set_lladdr_and_type(ifnet_t interface, const void* lladdr, size_t length, u_char type);
#endif KERNEL_PRIVATE

/*!
	@function ifnet_add_multicast
	@discussion Joins a multicast and returns an ifmultiaddr_t with the
		reference count incremented for you. You are responsible for
		decrementing the reference count after calling
		ifnet_remove_multicast and making sure you no longer have any
		references to the multicast.
	@param interface The interface.
	@param maddr The multicast address to join. Either a physical
		address or logical address to be translated to a physical
		address.
	@param multicast The resulting ifmultiaddr_t multicast address.
	@result 0 on success otherwise the errno error.
 */
errno_t	ifnet_add_multicast(ifnet_t interface, const struct sockaddr *maddr,
							ifmultiaddr_t *multicast);

/*!
	@function ifnet_remove_multicast
	@discussion Causes the interface to leave the multicast group. The
		stack keeps track of how many times ifnet_add_multicast has been
		called for a given multicast address. The multicast will only be
		removed when the number of times ifnet_remove_multicast has been
		called matches the number of times ifnet_add_multicast has been
		called.
		
		The memory for the multicast address is not actually freed until
		the separate reference count has reached zero. Some parts of the
		stack may keep a pointer to the multicast even after that
		multicast has been removed from the interface.
		
		When an interface is detached, all of the multicasts are
		removed. If the interface of the multicast passed in is no
		longer attached, this function will gracefully return,
		performing no work.
		
		It is the callers responsibility to release the multicast
		address after calling this function.
	@param multicast The multicast to be removed.
	@result 0 on success otherwise the errno error.
 */
errno_t	ifnet_remove_multicast(ifmultiaddr_t multicast);

/*!
	@function ifnet_get_multicast_list
	@discussion Retrieves a list of multicast address the interface is
		set to receive. This function allocates and returns an array of
		references to the various multicast addresses. The multicasts
		have their reference counts bumped on your behalf. Calling
		ifnet_free_multicast_list will decrement the reference counts
		and free the array.
	@param interface The interface.
	@param multicasts A pointer to a NULL terminated array of references
		to the multicast addresses.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_get_multicast_list(ifnet_t interface, ifmultiaddr_t **addresses);

/*!
	@function ifnet_free_multicast_list
	@discussion Frees a list of multicasts returned by
		ifnet_get_multicast_list. Decrements the refcount on each
		multicast address and frees the array.
	@param multicasts An array of references to the multicast addresses.
	@result 0 on success otherwise the errno error.
 */
void ifnet_free_multicast_list(ifmultiaddr_t *multicasts);

/*!
	@function ifnet_find_by_name
	@discussion Find an interface by the name including the unit number.
		Caller must call ifnet_release on any non-null interface return
		value.
	@param name The name of the interface, including any unit number
		(i.e. "en0").
	@param interface A pointer to an interface reference. This will be
		filled in if a matching interface is found.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_find_by_name(const char *ifname, ifnet_t *interface);

/*!
	@function ifnet_list_get
	@discussion Get a list of attached interfaces. List will be set to
		point to an array allocated by ifnet_list_get. The interfaces
		are refcounted and the counts will be incremented before the
		function returns. The list of interfaces must be freed using
		ifnet_list_free.
	@param family The interface family (i.e. IFNET_FAMILY_ETHERNET). To
		find interfaces of all families, use IFNET_FAMILY_ANY.
	@param interfaces A pointer to an array of interface references.
	@param count A pointer that will be filled in with the number of
		matching interfaces in the array.
	@result 0 on success otherwise the errno error.
 */
errno_t ifnet_list_get(ifnet_family_t family, ifnet_t **interfaces, u_int32_t *count);

/*!
	@function ifnet_list_free
	@discussion Free a list of interfaces returned by ifnet_list_get.
		Decrements the reference count on each interface and frees the
		array of references. If you keep a reference to an interface, be
		sure to increment the reference count before calling
		ifnet_list_free.
	@param interfaces An array of interface references from ifnet_list_get.
 */
void ifnet_list_free(ifnet_t *interfaces);

/********************************************************************************************/
/* ifaddr_t accessors																		*/
/********************************************************************************************/

/*!
	@function ifaddr_reference
	@discussion Increment the reference count of an address tied to an
		interface.
	@param ifaddr The interface address.
	@result 0 upon success
 */
errno_t	ifaddr_reference(ifaddr_t ifaddr);

/*!
	@function ifaddr_release
	@discussion Decrements the reference count of and possibly frees an
		address tied to an interface.
	@param ifaddr The interface address.
	@result 0 upon success
 */
errno_t	ifaddr_release(ifaddr_t ifaddr);

/*!
	@function ifaddr_address
	@discussion Copies the address out of the ifaddr.
	@param ifaddr The interface address.
	@param out_addr The sockaddr storage for the address.
	@param addr_size The size of the storage for the address.
	@result 0 upon success
 */
errno_t	ifaddr_address(ifaddr_t ifaddr, struct sockaddr *out_addr, u_int32_t addr_size);

/*!
	@function ifaddr_address
	@discussion Returns the address family of the address.
	@param ifaddr The interface address.
	@result 0 on failure, address family on success.
 */
sa_family_t	ifaddr_address_family(ifaddr_t ifaddr);

/*!
	@function ifaddr_dstaddress
	@discussion Copies the destination address out of the ifaddr.
	@param ifaddr The interface address.
	@param out_dstaddr The sockaddr storage for the destination address.
	@param dstaddr_size The size of the storage for the destination address.
	@result 0 upon success
 */
errno_t	ifaddr_dstaddress(ifaddr_t ifaddr, struct sockaddr *out_dstaddr, u_int32_t dstaddr_size);

/*!
	@function ifaddr_netmask
	@discussion Copies the netmask out of the ifaddr.
	@param ifaddr The interface address.
	@param out_netmask The sockaddr storage for the netmask.
	@param netmask_size The size of the storage for the netmask.
	@result 0 upon success
 */
errno_t	ifaddr_netmask(ifaddr_t ifaddr, struct sockaddr *out_netmask, u_int32_t netmask_size);

/*!
	@function ifaddr_ifnet
	@discussion Returns the interface the address is attached to. The
		reference is only valid until the ifaddr is released. If you
		need to hold a reference to the ifnet for longer than you hold a
		reference to the ifaddr, increment the reference using
		ifnet_reference.
	@param ifaddr The interface address.
	@result A reference to the interface the address is attached to.
 */
ifnet_t	ifaddr_ifnet(ifaddr_t ifaddr);

/*!
	@function ifaddr_withaddr
	@discussion Returns an interface address with the address specified.
		Increments the reference count on the ifaddr before returning to
		the caller. Caller is responsible for calling ifaddr_release.
	@param address The address to search for.
	@result A reference to the interface address.
 */
ifaddr_t	ifaddr_withaddr(const struct sockaddr* address);

/*!
	@function ifaddr_withdstaddr
	@discussion Returns an interface address for the interface address
		that matches the destination when the netmask is applied.
		Increments the reference count on the ifaddr before returning to
		the caller. Caller is responsible for calling ifaddr_release.
	@param destination The destination to search for.
	@result A reference to the interface address.
 */
ifaddr_t	ifaddr_withdstaddr(const struct sockaddr* destination);

/*!
	@function ifaddr_withnet
	@discussion Returns an interface address for the interface with the
		network described by net. Increments the reference count on the
		ifaddr before returning to the caller. Caller is responsible for
		calling ifaddr_release.
	@param net The network to search for.
	@result A reference to the interface address.
 */
ifaddr_t	ifaddr_withnet(const struct sockaddr* net);

/*!
	@function ifaddr_withroute
	@discussion Returns an interface address given a destination and
		gateway. Increments the reference count on the ifaddr before
		returning to the caller. Caller is responsible for calling
		ifaddr_release.
	@param flags Routing flags. See net/route.h, RTF_GATEWAY etc.
	@param destination The destination to search for.
	@param gateway A gateway to search for.
	@result A reference to the interface address.
 */
ifaddr_t	ifaddr_withroute(int flags, const struct sockaddr* destination,
							 const struct sockaddr* gateway);

/*!
	@function ifaddr_findbestforaddr
	@discussion Finds the best local address assigned to a specific
		interface to use when communicating with another address.
		Increments the reference count on the ifaddr before returning to
		the caller. Caller is responsible for calling ifaddr_release.
	@param addr The remote address.
	@param interface The local interface.
	@result A reference to the interface address.
 */
ifaddr_t	ifaddr_findbestforaddr(const struct sockaddr *addr, ifnet_t interface);

/********************************************************************************************/
/* ifmultiaddr_t accessors																	*/
/********************************************************************************************/

/*!
	@function ifmaddr_reference
	@discussion Increment the reference count of an interface multicast
		address.
	@param ifmaddr The interface multicast address.
	@result 0 on success. Only error will be EINVAL if ifmaddr is not valid.
 */
errno_t	ifmaddr_reference(ifmultiaddr_t ifmaddr);

/*!
	@function ifmaddr_release
	@discussion Decrement the reference count of an interface multicast
		address. If the reference count reaches zero, the ifmultiaddr
		will be removed from the interface and the ifmultiaddr will be
		freed.
	@param ifmaddr The interface multicast address.
	@result 0 on success. Only error will be EINVAL if ifmaddr is not valid.
 */
errno_t	ifmaddr_release(ifmultiaddr_t ifmaddr);

/*!
	@function ifmaddr_address
	@discussion Copies the multicast address to out_multicast.
	@param out_multicast Storage for a sockaddr.
	@param addr_size Size of the storage.
	@result 0 on success.
 */
errno_t	ifmaddr_address(ifmultiaddr_t ifmaddr, struct sockaddr *out_multicast, u_int32_t addr_size);

/*!
	@function ifmaddr_lladdress
	@discussion Copies the link layer multicast address to
		out_link_layer_multicast.
	@param out_link_layer_multicast Storage for a sockaddr.
	@param addr_size Size of the storage.
	@result 0 on success.
 */
errno_t	ifmaddr_lladdress(ifmultiaddr_t ifmaddr, struct sockaddr *out_link_layer_multicast,
						  u_int32_t addr_size);

/*!
	@function ifmaddr_ifnet
	@discussion Returns the interface this multicast address is attached
		to. The interface reference count is not bumped by this
		function. The interface is only valid as long as you don't
		release the refernece to the multiast address. If you need to
		maintain your pointer to the ifnet, call ifnet_reference
		followed by ifnet_release when you're finished.
	@param ifmaddr The interface multicast address.
	@result A reference to the interface.
 */
ifnet_t	ifmaddr_ifnet(ifmultiaddr_t ifmaddr);

__END_DECLS

#endif
