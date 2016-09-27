/*
 * Copyright (c) 2012-2015 Apple Inc. All rights reserved.
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

#include <sys/systm.h>
#include <sys/kern_control.h>
#include <net/kpi_protocol.h>
#include <net/kpi_interface.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/if_ipsec.h>
#include <sys/mbuf.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <sys/kauth.h>
#include <netinet6/ipsec.h>
#include <netinet6/ipsec6.h>
#include <netinet/ip.h>
#include <net/flowadv.h>
#include <net/necp.h>
#include <netkey/key.h>
#include <net/pktap.h>

extern int net_qos_policy_restricted;
extern int net_qos_policy_restrict_avapps;

/* Kernel Control functions */
static errno_t	ipsec_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac,
								  void **unitinfo);
static errno_t	ipsec_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t unit,
									 void *unitinfo);
static errno_t	ipsec_ctl_send(kern_ctl_ref kctlref, u_int32_t unit,
							   void *unitinfo, mbuf_t m, int flags);
static errno_t	ipsec_ctl_getopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
								 int opt, void *data, size_t *len);
static errno_t	ipsec_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
								 int opt, void *data, size_t len);

/* Network Interface functions */
static void     ipsec_start(ifnet_t	interface);
static errno_t	ipsec_output(ifnet_t interface, mbuf_t data);
static errno_t	ipsec_demux(ifnet_t interface, mbuf_t data, char *frame_header,
							protocol_family_t *protocol);
static errno_t	ipsec_add_proto(ifnet_t interface, protocol_family_t protocol,
								const struct ifnet_demux_desc *demux_array,
								u_int32_t demux_count);
static errno_t	ipsec_del_proto(ifnet_t interface, protocol_family_t protocol);
static errno_t	ipsec_ioctl(ifnet_t interface, u_long cmd, void *data);
static void		ipsec_detached(ifnet_t interface);

/* Protocol handlers */
static errno_t	ipsec_attach_proto(ifnet_t interface, protocol_family_t proto);
static errno_t	ipsec_proto_input(ifnet_t interface, protocol_family_t protocol,
								  mbuf_t m, char *frame_header);
static errno_t ipsec_proto_pre_output(ifnet_t interface, protocol_family_t protocol,
									  mbuf_t *packet, const struct sockaddr *dest, void *route,
									  char *frame_type, char *link_layer_dest);

static kern_ctl_ref	ipsec_kctlref;
static u_int32_t	ipsec_family;

#define IPSECQ_MAXLEN 256

errno_t
ipsec_register_control(void)
{
	struct kern_ctl_reg	kern_ctl;
	errno_t				result = 0;
	
	/* Find a unique value for our interface family */
	result = mbuf_tag_id_find(IPSEC_CONTROL_NAME, &ipsec_family);
	if (result != 0) {
		printf("ipsec_register_control - mbuf_tag_id_find_internal failed: %d\n", result);
		return result;
	}
	
	bzero(&kern_ctl, sizeof(kern_ctl));
	strlcpy(kern_ctl.ctl_name, IPSEC_CONTROL_NAME, sizeof(kern_ctl.ctl_name));
	kern_ctl.ctl_name[sizeof(kern_ctl.ctl_name) - 1] = 0;
	kern_ctl.ctl_flags = CTL_FLAG_PRIVILEGED; /* Require root */
	kern_ctl.ctl_sendsize = 64 * 1024;
	kern_ctl.ctl_recvsize = 64 * 1024;
	kern_ctl.ctl_connect = ipsec_ctl_connect;
	kern_ctl.ctl_disconnect = ipsec_ctl_disconnect;
	kern_ctl.ctl_send = ipsec_ctl_send;
	kern_ctl.ctl_setopt = ipsec_ctl_setopt;
	kern_ctl.ctl_getopt = ipsec_ctl_getopt;
	
	result = ctl_register(&kern_ctl, &ipsec_kctlref);
	if (result != 0) {
		printf("ipsec_register_control - ctl_register failed: %d\n", result);
		return result;
	}
	
	/* Register the protocol plumbers */
	if ((result = proto_register_plumber(PF_INET, ipsec_family,
										 ipsec_attach_proto, NULL)) != 0) {
		printf("ipsec_register_control - proto_register_plumber(PF_INET, %d) failed: %d\n",
			   ipsec_family, result);
		ctl_deregister(ipsec_kctlref);
		return result;
	}
	
	/* Register the protocol plumbers */
	if ((result = proto_register_plumber(PF_INET6, ipsec_family,
										 ipsec_attach_proto, NULL)) != 0) {
		proto_unregister_plumber(PF_INET, ipsec_family);
		ctl_deregister(ipsec_kctlref);
		printf("ipsec_register_control - proto_register_plumber(PF_INET6, %d) failed: %d\n",
			   ipsec_family, result);
		return result;
	}
	
	return 0;
}

/* Helpers */
int
ipsec_interface_isvalid (ifnet_t interface)
{
    struct ipsec_pcb *pcb = NULL;
    
    if (interface == NULL)
        return 0;
    
    pcb = ifnet_softc(interface);
    
    if (pcb == NULL)
        return 0;
    
    /* When ctl disconnects, ipsec_unit is set to 0 */
    if (pcb->ipsec_unit == 0)
        return 0;
    
    return 1;
}

/* Kernel control functions */

static errno_t
ipsec_ctl_connect(kern_ctl_ref		kctlref,
				  struct sockaddr_ctl	*sac,
				  void				**unitinfo)
{
	struct ifnet_init_eparams	ipsec_init;
	struct ipsec_pcb				*pcb;
	errno_t						result;
	struct ifnet_stats_param 	stats;
	
	/* kernel control allocates, interface frees */
	MALLOC(pcb, struct ipsec_pcb *, sizeof(*pcb), M_DEVBUF, M_WAITOK | M_ZERO);

	/* Setup the protocol control block */
	*unitinfo = pcb;
	pcb->ipsec_ctlref = kctlref;
	pcb->ipsec_unit = sac->sc_unit;
	pcb->ipsec_output_service_class = MBUF_SC_OAM;
	
	printf("ipsec_ctl_connect: creating interface ipsec%d\n", pcb->ipsec_unit - 1);
	
	/* Create the interface */
	bzero(&ipsec_init, sizeof(ipsec_init));
	ipsec_init.ver = IFNET_INIT_CURRENT_VERSION;
	ipsec_init.len = sizeof (ipsec_init);
	ipsec_init.name = "ipsec";
	ipsec_init.start = ipsec_start;
	ipsec_init.unit = pcb->ipsec_unit - 1;
	ipsec_init.family = ipsec_family;
	ipsec_init.type = IFT_OTHER;
	ipsec_init.demux = ipsec_demux;
	ipsec_init.add_proto = ipsec_add_proto;
	ipsec_init.del_proto = ipsec_del_proto;
	ipsec_init.softc = pcb;
	ipsec_init.ioctl = ipsec_ioctl;
	ipsec_init.detach = ipsec_detached;
	
	result = ifnet_allocate_extended(&ipsec_init, &pcb->ipsec_ifp);
	if (result != 0) {
		printf("ipsec_ctl_connect - ifnet_allocate failed: %d\n", result);
		*unitinfo = NULL;
		FREE(pcb, M_DEVBUF);
		return result;
	}
	
	/* Set flags and additional information. */
	ifnet_set_mtu(pcb->ipsec_ifp, 1500);
	ifnet_set_flags(pcb->ipsec_ifp, IFF_UP | IFF_MULTICAST | IFF_POINTOPOINT, 0xffff);
	
	/* The interface must generate its own IPv6 LinkLocal address,
	 * if possible following the recommendation of RFC2472 to the 64bit interface ID
	 */
	ifnet_set_eflags(pcb->ipsec_ifp, IFEF_NOAUTOIPV6LL, IFEF_NOAUTOIPV6LL);
	
	/* Reset the stats in case as the interface may have been recycled */
	bzero(&stats, sizeof(struct ifnet_stats_param));
	ifnet_set_stat(pcb->ipsec_ifp, &stats);
	
	/* Attach the interface */
	result = ifnet_attach(pcb->ipsec_ifp, NULL);
	if (result != 0) {
		printf("ipsec_ctl_connect - ifnet_allocate failed: %d\n", result);
		ifnet_release(pcb->ipsec_ifp);
		*unitinfo = NULL;
		FREE(pcb, M_DEVBUF);
	} else {
		/* Attach to bpf */
		bpfattach(pcb->ipsec_ifp, DLT_NULL, 4);
	
		/* The interfaces resoures allocated, mark it as running */
		ifnet_set_flags(pcb->ipsec_ifp, IFF_RUNNING, IFF_RUNNING);
	}
	
	return result;
}

static errno_t
ipsec_detach_ip(ifnet_t				interface,
				protocol_family_t	protocol,
				socket_t			pf_socket)
{
	errno_t result = EPROTONOSUPPORT;
	
	/* Attempt a detach */
	if (protocol == PF_INET) {
		struct ifreq	ifr;
		
		bzero(&ifr, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d",
				 ifnet_name(interface), ifnet_unit(interface));
		
		result = sock_ioctl(pf_socket, SIOCPROTODETACH, &ifr);
	}
	else if (protocol == PF_INET6) {
		struct in6_ifreq	ifr6;
		
		bzero(&ifr6, sizeof(ifr6));
		snprintf(ifr6.ifr_name, sizeof(ifr6.ifr_name), "%s%d",
				 ifnet_name(interface), ifnet_unit(interface));
		
		result = sock_ioctl(pf_socket, SIOCPROTODETACH_IN6, &ifr6);
	}
	
	return result;
}

static void
ipsec_remove_address(ifnet_t				interface,
					 protocol_family_t	protocol,
					 ifaddr_t			address,
					 socket_t			pf_socket)
{
	errno_t result = 0;
	
	/* Attempt a detach */
	if (protocol == PF_INET) {
		struct ifreq	ifr;
		
		bzero(&ifr, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d",
				 ifnet_name(interface), ifnet_unit(interface));
		result = ifaddr_address(address, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
		if (result != 0) {
			printf("ipsec_remove_address - ifaddr_address failed: %d", result);
		}
		else {
			result = sock_ioctl(pf_socket, SIOCDIFADDR, &ifr);
			if (result != 0) {
				printf("ipsec_remove_address - SIOCDIFADDR failed: %d", result);
			}
		}
	}
	else if (protocol == PF_INET6) {
		struct in6_ifreq	ifr6;
		
		bzero(&ifr6, sizeof(ifr6));
		snprintf(ifr6.ifr_name, sizeof(ifr6.ifr_name), "%s%d",
				 ifnet_name(interface), ifnet_unit(interface));
		result = ifaddr_address(address, (struct sockaddr*)&ifr6.ifr_addr,
								sizeof(ifr6.ifr_addr));
		if (result != 0) {
			printf("ipsec_remove_address - ifaddr_address failed (v6): %d",
				   result);
		}
		else {
			result = sock_ioctl(pf_socket, SIOCDIFADDR_IN6, &ifr6);
			if (result != 0) {
				printf("ipsec_remove_address - SIOCDIFADDR_IN6 failed: %d",
					   result);
			}
		}
	}
}

static void
ipsec_cleanup_family(ifnet_t				interface,
					 protocol_family_t	protocol)
{
	errno_t		result = 0;
	socket_t	pf_socket = NULL;
	ifaddr_t	*addresses = NULL;
	int			i;
	
	if (protocol != PF_INET && protocol != PF_INET6) {
		printf("ipsec_cleanup_family - invalid protocol family %d\n", protocol);
		return;
	}
	
	/* Create a socket for removing addresses and detaching the protocol */
	result = sock_socket(protocol, SOCK_DGRAM, 0, NULL, NULL, &pf_socket);
	if (result != 0) {
		if (result != EAFNOSUPPORT)
			printf("ipsec_cleanup_family - failed to create %s socket: %d\n",
				   protocol == PF_INET ? "IP" : "IPv6", result);
		goto cleanup;
	}
	
	/* always set SS_PRIV, we want to close and detach regardless */
	sock_setpriv(pf_socket, 1);
	
	result = ipsec_detach_ip(interface, protocol, pf_socket);
	if (result == 0 || result == ENXIO) {
		/* We are done! We either detached or weren't attached. */
		goto cleanup;
	}
	else if (result != EBUSY) {
		/* Uh, not really sure what happened here... */
		printf("ipsec_cleanup_family - ipsec_detach_ip failed: %d\n", result);
		goto cleanup;
	}
	
	/*
	 * At this point, we received an EBUSY error. This means there are
	 * addresses attached. We should detach them and then try again.
	 */
	result = ifnet_get_address_list_family(interface, &addresses, protocol);
	if (result != 0) {
		printf("fnet_get_address_list_family(%s%d, 0xblah, %s) - failed: %d\n",
			   ifnet_name(interface), ifnet_unit(interface),
			   protocol == PF_INET ? "PF_INET" : "PF_INET6", result);
		goto cleanup;
	}
	
	for (i = 0; addresses[i] != 0; i++) {
		ipsec_remove_address(interface, protocol, addresses[i], pf_socket);
	}
	ifnet_free_address_list(addresses);
	addresses = NULL;
	
	/*
	 * The addresses should be gone, we should try the remove again.
	 */
	result = ipsec_detach_ip(interface, protocol, pf_socket);
	if (result != 0 && result != ENXIO) {
		printf("ipsec_cleanup_family - ipsec_detach_ip failed: %d\n", result);
	}
	
cleanup:
	if (pf_socket != NULL)
		sock_close(pf_socket);
	
	if (addresses != NULL)
		ifnet_free_address_list(addresses);
}

static errno_t
ipsec_ctl_disconnect(__unused kern_ctl_ref	kctlref,
					 __unused u_int32_t		unit,
					 void					*unitinfo)
{
	struct ipsec_pcb	*pcb = unitinfo;
	ifnet_t			ifp = NULL;
	errno_t			result = 0;

	if (pcb == NULL)
		return EINVAL;

	ifp = pcb->ipsec_ifp;
	VERIFY(ifp != NULL);
	pcb->ipsec_ctlref = NULL;
	pcb->ipsec_unit = 0;
	
	/*
	 * We want to do everything in our power to ensure that the interface
	 * really goes away when the socket is closed. We must remove IP/IPv6
	 * addresses and detach the protocols. Finally, we can remove and
	 * release the interface.
	 */
	key_delsp_for_ipsec_if(ifp);
    
	ipsec_cleanup_family(ifp, AF_INET);
	ipsec_cleanup_family(ifp, AF_INET6);
	
	if ((result = ifnet_detach(ifp)) != 0) {
		printf("ipsec_ctl_disconnect - ifnet_detach failed: %d\n", result);
	}
	
	return 0;
}

static errno_t
ipsec_ctl_send(__unused kern_ctl_ref	kctlref,
			   __unused u_int32_t		unit,
			   __unused void			*unitinfo,
			   mbuf_t                  m,
			   __unused int			flags)
{
    /* Receive messages from the control socket. Currently unused. */
    mbuf_freem(m);
	return 0;
}

static errno_t
ipsec_ctl_setopt(__unused kern_ctl_ref	kctlref,
				 __unused u_int32_t		unit,
				 void					*unitinfo,
				 int						opt,
				 void					*data,
				 size_t					len)
{
	struct ipsec_pcb			*pcb = unitinfo;
	errno_t					result = 0;
	
	/* check for privileges for privileged options */
	switch (opt) {
		case IPSEC_OPT_FLAGS:
		case IPSEC_OPT_EXT_IFDATA_STATS:
		case IPSEC_OPT_SET_DELEGATE_INTERFACE:
		case IPSEC_OPT_OUTPUT_TRAFFIC_CLASS:
			if (kauth_cred_issuser(kauth_cred_get()) == 0) {
				return EPERM;
			}
			break;
	}
	
	switch (opt) {
		case IPSEC_OPT_FLAGS:
			if (len != sizeof(u_int32_t))
				result = EMSGSIZE;
			else
				pcb->ipsec_flags = *(u_int32_t *)data;
			break;
			
		case IPSEC_OPT_EXT_IFDATA_STATS:
			if (len != sizeof(int)) {
				result = EMSGSIZE;
				break;
			}
			pcb->ipsec_ext_ifdata_stats = (*(int *)data) ? 1 : 0;
			break;
			
		case IPSEC_OPT_INC_IFDATA_STATS_IN:
		case IPSEC_OPT_INC_IFDATA_STATS_OUT: {
			struct ipsec_stats_param *utsp = (struct ipsec_stats_param *)data;
			
			if (utsp == NULL || len < sizeof(struct ipsec_stats_param)) {
				result = EINVAL;
				break;
			}
			if (!pcb->ipsec_ext_ifdata_stats) {
				result = EINVAL;
				break;
			}
			if (opt == IPSEC_OPT_INC_IFDATA_STATS_IN)
				ifnet_stat_increment_in(pcb->ipsec_ifp, utsp->utsp_packets,
										utsp->utsp_bytes, utsp->utsp_errors);
			else
				ifnet_stat_increment_out(pcb->ipsec_ifp, utsp->utsp_packets,
										 utsp->utsp_bytes, utsp->utsp_errors);
			break;
		}
		
		case IPSEC_OPT_SET_DELEGATE_INTERFACE: {
			ifnet_t		del_ifp = NULL;
			char            name[IFNAMSIZ];
			
			if (len > IFNAMSIZ - 1) {
				result = EMSGSIZE;
				break;
			}
			if (len != 0) {   /* if len==0, del_ifp will be NULL causing the delegate to be removed */
				bcopy(data, name, len);
				name[len] = 0;
				result = ifnet_find_by_name(name, &del_ifp);
			}
			if (result == 0) {
				printf("%s IPSEC_OPT_SET_DELEGATE_INTERFACE %s to %s\n",
					__func__, pcb->ipsec_ifp->if_xname, 
					del_ifp->if_xname);

				result = ifnet_set_delegate(pcb->ipsec_ifp, del_ifp);
				if (del_ifp)
					ifnet_release(del_ifp);
			}
			break;
		}
			
		case IPSEC_OPT_OUTPUT_TRAFFIC_CLASS: {
			if (len != sizeof(int)) {
				result = EMSGSIZE;
				break;
			}
			mbuf_svc_class_t output_service_class = so_tc2msc(*(int *)data);
			if (output_service_class == MBUF_SC_UNSPEC) {
				pcb->ipsec_output_service_class = MBUF_SC_OAM;
			} else {
				pcb->ipsec_output_service_class = output_service_class;
			}
			printf("%s IPSEC_OPT_OUTPUT_TRAFFIC_CLASS %s svc %d\n",
				__func__, pcb->ipsec_ifp->if_xname, 
				pcb->ipsec_output_service_class);
			break;
		}
			
		default:
			result = ENOPROTOOPT;
			break;
	}
	
	return result;
}

static errno_t
ipsec_ctl_getopt(__unused kern_ctl_ref	kctlref,
				 __unused u_int32_t		unit,
				 void					*unitinfo,
				 int						opt,
				 void					*data,
				 size_t					*len)
{
	struct ipsec_pcb			*pcb = unitinfo;
	errno_t					result = 0;
	
	switch (opt) {
		case IPSEC_OPT_FLAGS:
			if (*len != sizeof(u_int32_t))
				result = EMSGSIZE;
			else
				*(u_int32_t *)data = pcb->ipsec_flags;
			break;
			
		case IPSEC_OPT_EXT_IFDATA_STATS:
			if (*len != sizeof(int))
				result = EMSGSIZE;
			else
				*(int *)data = (pcb->ipsec_ext_ifdata_stats) ? 1 : 0;
			break;
			
		case IPSEC_OPT_IFNAME:
			*len = snprintf(data, *len, "%s%d", ifnet_name(pcb->ipsec_ifp), ifnet_unit(pcb->ipsec_ifp)) + 1;
			break;
			
		case IPSEC_OPT_OUTPUT_TRAFFIC_CLASS: {
			if (*len != sizeof(int)) {
				result = EMSGSIZE;
				break;
			}
			*(int *)data = so_svc2tc(pcb->ipsec_output_service_class);
			break;
		}
		default:
			result = ENOPROTOOPT;
			break;
	}
	
	return result;
}

/* Network Interface functions */
static errno_t
ipsec_output(ifnet_t	interface,
             mbuf_t     data)
{
	struct ipsec_pcb	*pcb = ifnet_softc(interface);
    struct ipsec_output_state ipsec_state;
    struct route ro;
    struct route_in6 ro6;
    int	length;
    struct ip *ip;
    struct ip6_hdr *ip6;
    struct ip_out_args ipoa;
    struct ip6_out_args ip6oa;
    int error = 0;
    u_int ip_version = 0;
    uint32_t af;
    int flags = 0;
    struct flowadv *adv = NULL;
    
	// Make sure this packet isn't looping through the interface
	if (necp_get_last_interface_index_from_packet(data) == interface->if_index) {
		error = -1;
		goto ipsec_output_err;
	}
	
	// Mark the interface so NECP can evaluate tunnel policy
	necp_mark_packet_from_interface(data, interface);
	
    ip = mtod(data, struct ip *);
    ip_version = ip->ip_v;
	
    switch (ip_version) {
        case 4:
            /* Tap */
            af = AF_INET;
            bpf_tap_out(pcb->ipsec_ifp, DLT_NULL, data, &af, sizeof(af));
			
            /* Apply encryption */
            bzero(&ipsec_state, sizeof(ipsec_state));
            ipsec_state.m = data;
            ipsec_state.dst = (struct sockaddr *)&ip->ip_dst;
            bzero(&ipsec_state.ro, sizeof(ipsec_state.ro));
			
            error = ipsec4_interface_output(&ipsec_state, interface);
            /* Tunneled in IPv6 - packet is gone */
            if (error == 0 && ipsec_state.tunneled == 6) {
                goto done;
            }

            data = ipsec_state.m;
            if (error || data == NULL) {
                printf("ipsec_output: ipsec4_output error %d.\n", error);
                goto ipsec_output_err;
            }
            
            /* Set traffic class, set flow */
            m_set_service_class(data, pcb->ipsec_output_service_class);
            data->m_pkthdr.pkt_flowsrc = FLOWSRC_IFNET;
            data->m_pkthdr.pkt_flowid = interface->if_flowhash;
            data->m_pkthdr.pkt_proto = ip->ip_p;
            data->m_pkthdr.pkt_flags = (PKTF_FLOW_ID | PKTF_FLOW_ADV | PKTF_FLOW_LOCALSRC);
            
            /* Flip endian-ness for ip_output */
            ip = mtod(data, struct ip *);
            NTOHS(ip->ip_len);
            NTOHS(ip->ip_off);
            
            /* Increment statistics */
            length = mbuf_pkthdr_len(data);
            ifnet_stat_increment_out(interface, 1, length, 0);
			
            /* Send to ip_output */
            bzero(&ro, sizeof(ro));
			
            flags = IP_OUTARGS |	/* Passing out args to specify interface */
			IP_NOIPSEC;				/* To ensure the packet doesn't go through ipsec twice */
			
            bzero(&ipoa, sizeof(ipoa));
            ipoa.ipoa_flowadv.code = 0;
            ipoa.ipoa_flags = IPOAF_SELECT_SRCIF | IPOAF_BOUND_SRCADDR;
            if (ipsec_state.outgoing_if) {
                ipoa.ipoa_boundif = ipsec_state.outgoing_if;
                ipoa.ipoa_flags |= IPOAF_BOUND_IF;
            }
            ipsec_set_ipoa_for_interface(pcb->ipsec_ifp, &ipoa);
            
            adv = &ipoa.ipoa_flowadv;
            
            (void) ip_output(data, NULL, &ro, flags, NULL, &ipoa);
            data = NULL;
            
            if (adv->code == FADV_FLOW_CONTROLLED || adv->code == FADV_SUSPENDED) {
                error = ENOBUFS;
                ifnet_disable_output(interface);
            }
            
            goto done;
        case 6:
            af = AF_INET6;
            bpf_tap_out(pcb->ipsec_ifp, DLT_NULL, data, &af, sizeof(af));
            
            data = ipsec6_splithdr(data);
			if (data == NULL) {
				printf("ipsec_output: ipsec6_splithdr returned NULL\n");
				goto ipsec_output_err;
			}

            ip6 = mtod(data, struct ip6_hdr *);
			
            bzero(&ipsec_state, sizeof(ipsec_state));
            ipsec_state.m = data;
            ipsec_state.dst = (struct sockaddr *)&ip6->ip6_dst;
            bzero(&ipsec_state.ro, sizeof(ipsec_state.ro));
            
            error = ipsec6_interface_output(&ipsec_state, interface, &ip6->ip6_nxt, ipsec_state.m);
            if (error == 0 && ipsec_state.tunneled == 4)	/* tunneled in IPv4 - packet is gone */
				goto done;
            data = ipsec_state.m;
            if (error || data == NULL) {
                printf("ipsec_output: ipsec6_output error %d.\n", error);
                goto ipsec_output_err;
            }
            
            /* Set traffic class, set flow */
            m_set_service_class(data, pcb->ipsec_output_service_class);
            data->m_pkthdr.pkt_flowsrc = FLOWSRC_IFNET;
            data->m_pkthdr.pkt_flowid = interface->if_flowhash;
            data->m_pkthdr.pkt_proto = ip6->ip6_nxt;
            data->m_pkthdr.pkt_flags = (PKTF_FLOW_ID | PKTF_FLOW_ADV | PKTF_FLOW_LOCALSRC);
            
            /* Increment statistics */
            length = mbuf_pkthdr_len(data);
            ifnet_stat_increment_out(interface, 1, length, 0);
            
            /* Send to ip6_output */
            bzero(&ro6, sizeof(ro6));
            
            flags = IPV6_OUTARGS;
            
            bzero(&ip6oa, sizeof(ip6oa));
            ip6oa.ip6oa_flowadv.code = 0;
            ip6oa.ip6oa_flags = IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_SRCADDR;
            if (ipsec_state.outgoing_if) {
                ip6oa.ip6oa_boundif = ipsec_state.outgoing_if;
                ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;
            }
            ipsec_set_ip6oa_for_interface(pcb->ipsec_ifp, &ip6oa);
            
            adv = &ip6oa.ip6oa_flowadv;
            
            (void) ip6_output(data, NULL, &ro6, flags, NULL, NULL, &ip6oa);
            data = NULL;
            
            if (adv->code == FADV_FLOW_CONTROLLED || adv->code == FADV_SUSPENDED) {
                error = ENOBUFS;
                ifnet_disable_output(interface);
            }
            
            goto done;
        default:
            printf("ipsec_output: Received unknown packet version %d.\n", ip_version);
            error = -1;
            goto ipsec_output_err;
    }
	
done:
    return error;
    
ipsec_output_err:
    if (data)
        mbuf_freem(data);
	goto done;
}

static void
ipsec_start(ifnet_t	interface)
{
	mbuf_t data;

	for (;;) {
		if (ifnet_dequeue(interface, &data) != 0)
			break;
		if (ipsec_output(interface, data) != 0)
			break;
	}
}

/* Network Interface functions */
static errno_t
ipsec_demux(__unused ifnet_t	interface,
			mbuf_t				data,
			__unused char		*frame_header,
			protocol_family_t	*protocol)
{
    struct ip *ip;
    u_int ip_version;
    
	while (data != NULL && mbuf_len(data) < 1) {
		data = mbuf_next(data);
	}
	
	if (data == NULL)
		return ENOENT;
    
    ip = mtod(data, struct ip *);
    ip_version = ip->ip_v;
    
    switch(ip_version) {
		case 4:
            *protocol = PF_INET;
			return 0;
		case 6:
            *protocol = PF_INET6;
			return 0;
		default:
			break;
	}
	
	return 0;
}

static errno_t
ipsec_add_proto(__unused ifnet_t						interface,
				protocol_family_t						protocol,
				__unused const struct ifnet_demux_desc	*demux_array,
				__unused u_int32_t						demux_count)
{
	switch(protocol) {
		case PF_INET:
			return 0;
		case PF_INET6:
			return 0;
		default:
			break;
	}
	
	return ENOPROTOOPT;
}

static errno_t
ipsec_del_proto(__unused ifnet_t 			interface,
				__unused protocol_family_t	protocol)
{
	return 0;
}

static errno_t
ipsec_ioctl(ifnet_t		interface,
			u_long		command,
			void		*data)
{
	errno_t	result = 0;
	
	switch(command) {
		case SIOCSIFMTU:
			ifnet_set_mtu(interface, ((struct ifreq*)data)->ifr_mtu);
			break;
			
		case SIOCSIFFLAGS:
			/* ifioctl() takes care of it */
			break;
			
		default:
			result = EOPNOTSUPP;
	}
	
	return result;
}

static void
ipsec_detached(
			   ifnet_t	interface)
{
	struct ipsec_pcb	*pcb = ifnet_softc(interface);
    
	ifnet_release(pcb->ipsec_ifp);
}

/* Protocol Handlers */

static errno_t
ipsec_proto_input(ifnet_t interface,
				  protocol_family_t	protocol,
				  mbuf_t m,
				  __unused char *frame_header)
{
	struct ip *ip;
	uint32_t af = 0;
	ip = mtod(m, struct ip *);
	if (ip->ip_v == 4)
		af = AF_INET;
	else if (ip->ip_v == 6)
		af = AF_INET6;
	
	mbuf_pkthdr_setrcvif(m, interface);
	bpf_tap_in(interface, DLT_NULL, m, &af, sizeof(af));
	pktap_input(interface, protocol, m, NULL);

	if (proto_input(protocol, m) != 0) {
		ifnet_stat_increment_in(interface, 0, 0, 1);
		m_freem(m);
	} else {
		ifnet_stat_increment_in(interface, 1, m->m_pkthdr.len, 0);
	}
	
	return 0;
}

static errno_t
ipsec_proto_pre_output(__unused ifnet_t	interface,
					   protocol_family_t	protocol,
					   __unused mbuf_t		*packet,
					   __unused const struct sockaddr *dest,
					   __unused void *route,
					   __unused char *frame_type,
					   __unused char *link_layer_dest)
{
	
	*(protocol_family_t *)(void *)frame_type = protocol;
	return 0;
}

static errno_t
ipsec_attach_proto(ifnet_t				interface,
				   protocol_family_t	protocol)
{
	struct ifnet_attach_proto_param	proto;
	errno_t							result;
	
	bzero(&proto, sizeof(proto));
	proto.input = ipsec_proto_input;
	proto.pre_output = ipsec_proto_pre_output;
	
	result = ifnet_attach_protocol(interface, protocol, &proto);
	if (result != 0 && result != EEXIST) {
		printf("ipsec_attach_inet - ifnet_attach_protocol %d failed: %d\n",
			   protocol, result);
	}
	
	return result;
}

errno_t
ipsec_inject_inbound_packet(ifnet_t	interface,
							mbuf_t packet)
{
	errno_t error;
	protocol_family_t protocol;
	if ((error = ipsec_demux(interface, packet, NULL, &protocol)) != 0) {
		return error;
	}
	
	return ipsec_proto_input(interface, protocol, packet, NULL);
}

void
ipsec_set_pkthdr_for_interface(ifnet_t interface, mbuf_t packet, int family)
{
	if (packet != NULL && interface != NULL) {
		struct ipsec_pcb *pcb = ifnet_softc(interface);
		if (pcb != NULL) {
			/* Set traffic class, set flow */
			m_set_service_class(packet, pcb->ipsec_output_service_class);
			packet->m_pkthdr.pkt_flowsrc = FLOWSRC_IFNET;
			packet->m_pkthdr.pkt_flowid = interface->if_flowhash;
			if (family == AF_INET) {
				struct ip *ip = mtod(packet, struct ip *);
				packet->m_pkthdr.pkt_proto = ip->ip_p;
			} else if (family == AF_INET6) {
				struct ip6_hdr *ip6 = mtod(packet, struct ip6_hdr *);
				packet->m_pkthdr.pkt_proto = ip6->ip6_nxt;
			}
			packet->m_pkthdr.pkt_flags = (PKTF_FLOW_ID | PKTF_FLOW_ADV | PKTF_FLOW_LOCALSRC);
		}
	}
}

void
ipsec_set_ipoa_for_interface(ifnet_t interface, struct ip_out_args *ipoa)
{
	struct ipsec_pcb *pcb;
	
	if (interface == NULL || ipoa == NULL)
		return;
	pcb = ifnet_softc(interface);
	
	if (net_qos_policy_restricted == 0) {
		ipoa->ipoa_flags |= IPOAF_QOSMARKING_ALLOWED;
		ipoa->ipoa_sotc = so_svc2tc(pcb->ipsec_output_service_class);
	} else if (pcb->ipsec_output_service_class != MBUF_SC_VO ||
	   net_qos_policy_restrict_avapps != 0) {
		ipoa->ipoa_flags &= ~IPOAF_QOSMARKING_ALLOWED;
	} else {
		ipoa->ipoa_flags |= IP6OAF_QOSMARKING_ALLOWED;
		ipoa->ipoa_sotc = SO_TC_VO;
	}
}

void
ipsec_set_ip6oa_for_interface(ifnet_t interface, struct ip6_out_args *ip6oa)
{
	struct ipsec_pcb *pcb;
	
	if (interface == NULL || ip6oa == NULL)
		return;
	pcb = ifnet_softc(interface);
	
	if (net_qos_policy_restricted == 0) {
		ip6oa->ip6oa_flags |= IPOAF_QOSMARKING_ALLOWED;
		ip6oa->ip6oa_sotc = so_svc2tc(pcb->ipsec_output_service_class);
	} else if (pcb->ipsec_output_service_class != MBUF_SC_VO ||
	   net_qos_policy_restrict_avapps != 0) {
		ip6oa->ip6oa_flags &= ~IPOAF_QOSMARKING_ALLOWED;
	} else {
		ip6oa->ip6oa_flags |= IP6OAF_QOSMARKING_ALLOWED;
		ip6oa->ip6oa_sotc = SO_TC_VO;
	}
}
