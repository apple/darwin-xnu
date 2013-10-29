#include <kern/debug.h>

#if !NETWORKING

int bpf_attach(void);
int bpf_attach(void) 
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int bpf_tap_in(void);
int bpf_tap_in(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int bpf_tap_out(void);
int bpf_tap_out(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int bpfattach(void);
int bpfattach(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ctl_deregister(void);
int ctl_deregister(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ctl_enqueuedata(void);
int ctl_enqueuedata(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ctl_enqueuembuf(void);
int ctl_enqueuembuf(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ctl_getenqueuespace(void);
int ctl_getenqueuespace(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ctl_register(void);
int ctl_register(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ether_add_proto(void);
int ether_add_proto(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ether_check_multi(void);
int ether_check_multi(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ether_del_proto(void);
int ether_del_proto(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ether_demux(void);
int ether_demux(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ether_frameout(void);
int ether_frameout(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ether_ioctl(void);
int ether_ioctl(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int fifo_advlock(void);
int fifo_advlock(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int fifo_close(void);
int fifo_close(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int fifo_inactive(void);
int fifo_inactive(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int fifo_ioctl(void);
int fifo_ioctl(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int fifo_lookup(void);
int fifo_lookup(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int fifo_open(void);
int fifo_open(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int fifo_pathconf(void);
int fifo_pathconf(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int fifo_read(void);
int fifo_read(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int fifo_select(void);
int fifo_select(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int fifo_write(void);
int fifo_write(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_address(void);
int ifaddr_address(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_address_family(void);
int ifaddr_address_family(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_dstaddress(void);
int ifaddr_dstaddress(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_findbestforaddr(void);
int ifaddr_findbestforaddr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_ifnet(void);
int ifaddr_ifnet(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_netmask(void);
int ifaddr_netmask(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_reference(void);
int ifaddr_reference(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_release(void);
int ifaddr_release(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_withaddr(void);
int ifaddr_withaddr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_withdstaddr(void);
int ifaddr_withdstaddr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_withnet(void);
int ifaddr_withnet(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifaddr_withroute(void);
int ifaddr_withroute(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int iflt_attach(void);
int iflt_attach(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int iflt_detach(void);
int iflt_detach(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifmaddr_address(void);
int ifmaddr_address(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifmaddr_ifnet(void);
int ifmaddr_ifnet(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifmaddr_lladdress(void);
int ifmaddr_lladdress(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifmaddr_reference(void);
int ifmaddr_reference(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifmaddr_release(void);
int ifmaddr_release(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_add_multicast(void);
int ifnet_add_multicast(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_addrlen(void);
int ifnet_addrlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_allocate(void);
int ifnet_allocate(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_attach(void);
int ifnet_attach(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_attach_protocol(void);
int ifnet_attach_protocol(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_baudrate(void);
int ifnet_baudrate(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_capabilities_enabled(void);
int ifnet_capabilities_enabled(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_capabilities_supported(void);
int ifnet_capabilities_supported(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_detach(void);
int ifnet_detach(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_detach_protocol(void);
int ifnet_detach_protocol(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_eflags(void);
int ifnet_eflags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_event(void);
int ifnet_event(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_family(void);
int ifnet_family(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_subfamily(void);
int ifnet_subfamily(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_find_by_name(void);
int ifnet_find_by_name(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_flags(void);
int ifnet_flags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_free_address_list(void);
int ifnet_free_address_list(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_free_multicast_list(void);
int ifnet_free_multicast_list(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_address_list(void);
int ifnet_get_address_list(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_address_list_family(void);
int ifnet_get_address_list_family(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_link_mib_data(void);
int ifnet_get_link_mib_data(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_link_mib_data_length(void);
int ifnet_get_link_mib_data_length(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_multicast_list(void);
int ifnet_get_multicast_list(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_service_class_sndq_len(void);
int ifnet_get_service_class_sndq_len(void)
{
        panic("stub called in a config with no networking");
        return 0;
}

int ifnet_get_tso_mtu(void);
int ifnet_get_tso_mtu(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_wake_flags(void);
int ifnet_get_wake_flags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_hdrlen(void);
int ifnet_hdrlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_index(void);
int ifnet_index(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_input(void);
int ifnet_input(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_interface_family_find(void);
int ifnet_interface_family_find(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_ioctl(void);
int ifnet_ioctl(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_lastchange(void);
int ifnet_lastchange(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_list_free(void);
int ifnet_list_free(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_list_get(void);
int ifnet_list_get(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_lladdr(void);
int ifnet_lladdr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_lladdr_copy_bytes(void);
int ifnet_lladdr_copy_bytes(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_llbroadcast_copy_bytes(void);
int ifnet_llbroadcast_copy_bytes(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_metric(void);
int ifnet_metric(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_mtu(void);
int ifnet_mtu(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_name(void);
int ifnet_name(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_offload(void);
int ifnet_offload(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_output(void);
int ifnet_output(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_output_raw(void);
int ifnet_output_raw(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_reference(void);
int ifnet_reference(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_release(void);
int ifnet_release(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_remove_multicast(void);
int ifnet_remove_multicast(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_resolve_multicast(void);
int ifnet_resolve_multicast(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_addrlen(void);
int ifnet_set_addrlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_baudrate(void);
int ifnet_set_baudrate(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_capabilities_enabled(void);
int ifnet_set_capabilities_enabled(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_capabilities_supported(void);
int ifnet_set_capabilities_supported(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_delegate(void);
int ifnet_set_delegate(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_eflags(void);
int ifnet_set_eflags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_flags(void);
int ifnet_set_flags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_hdrlen(void);
int ifnet_set_hdrlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_link_mib_data(void);
int ifnet_set_link_mib_data(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_lladdr(void);
int ifnet_set_lladdr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_metric(void);
int ifnet_set_metric(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_mtu(void);
int ifnet_set_mtu(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_offload(void);
int ifnet_set_offload(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_promiscuous(void);
int ifnet_set_promiscuous(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_stat(void);
int ifnet_set_stat(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_tso_mtu(void);
int ifnet_set_tso_mtu(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_wake_flags(void);
int ifnet_set_wake_flags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_softc(void);
int ifnet_softc(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_stat(void);
int ifnet_stat(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_stat_increment(void);
int ifnet_stat_increment(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_stat_increment_in(void);
int ifnet_stat_increment_in(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_stat_increment_out(void);
int ifnet_stat_increment_out(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_touch_lastchange(void);
int ifnet_touch_lastchange(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_type(void);
int ifnet_type(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_unit(void);
int ifnet_unit(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int in_cksum(void);
int in_cksum(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int inet_arp_handle_input(void);
int inet_arp_handle_input(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int inet_arp_init_ifaddr(void);
int inet_arp_init_ifaddr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int inet_arp_lookup(void);
int inet_arp_lookup(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ipf_addv4(void);
int ipf_addv4(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ipf_addv6(void);
int ipf_addv6(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ipf_inject_input(void);
int ipf_inject_input(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ipf_inject_output(void);
int ipf_inject_output(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ipf_remove(void);
int ipf_remove(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int kev_msg_post(void);
int kev_msg_post(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int kev_vendor_code_find(void);
int kev_vendor_code_find(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_adj(void);
int mbuf_adj(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_adjustlen(void);
int mbuf_adjustlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_align_32(void);
int mbuf_align_32(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_alloccluster(void);
int mbuf_alloccluster(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_allocpacket(void);
int mbuf_allocpacket(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_allocpacket_list(void);
int mbuf_allocpacket_list(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_attachcluster(void);
int mbuf_attachcluster(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_clear_csum_performed(void);
int mbuf_clear_csum_performed(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_clear_csum_requested(void);
int mbuf_clear_csum_requested(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_clear_vlan_tag(void);
int mbuf_clear_vlan_tag(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_concatenate(void);
int mbuf_concatenate(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_copy_pkthdr(void);
int mbuf_copy_pkthdr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_copyback(void);
int mbuf_copyback(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_copydata(void);
int mbuf_copydata(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_copym(void);
int mbuf_copym(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_data(void);
int mbuf_data(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_data_to_physical(void);
int mbuf_data_to_physical(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_datastart(void);
int mbuf_datastart(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_dup(void);
int mbuf_dup(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_flags(void);
int mbuf_flags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_free(void);
int mbuf_free(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_freecluster(void);
int mbuf_freecluster(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_freem(void);
int mbuf_freem(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_freem_list(void);
int mbuf_freem_list(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get(void);
int mbuf_get(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_csum_performed(void);
int mbuf_get_csum_performed(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_csum_requested(void);
int mbuf_get_csum_requested(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_mhlen(void);
int mbuf_get_mhlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_minclsize(void);
int mbuf_get_minclsize(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_mlen(void);
int mbuf_get_mlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_traffic_class(void);
int mbuf_get_traffic_class(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_tso_requested(void);
int mbuf_get_tso_requested(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_vlan_tag(void);
int mbuf_get_vlan_tag(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_getcluster(void);
int mbuf_getcluster(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_gethdr(void);
int mbuf_gethdr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_getpacket(void);
int mbuf_getpacket(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_inbound_modified(void);
int mbuf_inbound_modified(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_inet_cksum(void);
int mbuf_inet_cksum(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_is_traffic_class_privileged(void);
int mbuf_is_traffic_class_privileged(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_leadingspace(void);
int mbuf_leadingspace(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_len(void);
int mbuf_len(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_maxlen(void);
int mbuf_maxlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_mclget(void);
int mbuf_mclget(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_mclhasreference(void);
int mbuf_mclhasreference(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_next(void);
int mbuf_next(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_nextpkt(void);
int mbuf_nextpkt(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_outbound_finalize(void);
int mbuf_outbound_finalize(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_pkthdr_adjustlen(void);
int mbuf_pkthdr_adjustlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_pkthdr_header(void);
int mbuf_pkthdr_header(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_pkthdr_len(void);
int mbuf_pkthdr_len(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_pkthdr_rcvif(void);
int mbuf_pkthdr_rcvif(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_pkthdr_setheader(void);
int mbuf_pkthdr_setheader(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_pkthdr_setlen(void);
int mbuf_pkthdr_setlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_pkthdr_setrcvif(void);
int mbuf_pkthdr_setrcvif(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_prepend(void);
int mbuf_prepend(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_pulldown(void);
int mbuf_pulldown(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_pullup(void);
int mbuf_pullup(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_set_csum_performed(void);
int mbuf_set_csum_performed(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_set_csum_requested(void);
int mbuf_set_csum_requested(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_set_traffic_class(void);
int mbuf_set_traffic_class(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_set_vlan_tag(void);
int mbuf_set_vlan_tag(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_setdata(void);
int mbuf_setdata(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_setflags(void);
int mbuf_setflags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_setflags_mask(void);
int mbuf_setflags_mask(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_setlen(void);
int mbuf_setlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_setnext(void);
int mbuf_setnext(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_setnextpkt(void);
int mbuf_setnextpkt(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_settype(void);
int mbuf_settype(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_split(void);
int mbuf_split(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_stats(void);
int mbuf_stats(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_tag_allocate(void);
int mbuf_tag_allocate(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_tag_find(void);
int mbuf_tag_find(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_tag_free(void);
int mbuf_tag_free(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_tag_id_find(void);
int mbuf_tag_id_find(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_add_drvaux(void);
int mbuf_add_drvaux(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_find_drvaux(void);
int mbuf_find_drvaux(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_del_drvaux(void);
int mbuf_del_drvaux(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_trailingspace(void);
int mbuf_trailingspace(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_type(void);
int mbuf_type(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int net_init_add(void);
int net_init_add(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int proto_inject(void);
int proto_inject(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int proto_input(void);
int proto_input(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int proto_register_plumber(void);
int proto_register_plumber(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int proto_unregister_plumber(void);
int proto_unregister_plumber(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sflt_attach(void);
int sflt_attach(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sflt_detach(void);
int sflt_detach(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sflt_register(void);
int sflt_register(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sflt_unregister(void);
int sflt_unregister(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_accept(void);
int sock_accept(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_bind(void);
int sock_bind(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_close(void);
int sock_close(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_connect(void);
int sock_connect(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_connectwait(void);
int sock_connectwait(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_getpeername(void);
int sock_getpeername(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_getsockname(void);
int sock_getsockname(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_getsockopt(void);
int sock_getsockopt(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_gettype(void);
int sock_gettype(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_inject_data_in(void);
int sock_inject_data_in(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_inject_data_out(void);
int sock_inject_data_out(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_ioctl(void);
int sock_ioctl(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_isconnected(void);
int sock_isconnected(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_isnonblocking(void);
int sock_isnonblocking(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_listen(void);
int sock_listen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_nointerrupt(void);
int sock_nointerrupt(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_receive(void);
int sock_receive(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_receivembuf(void);
int sock_receivembuf(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_send(void);
int sock_send(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_sendmbuf(void);
int sock_sendmbuf(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_setpriv(void);
int sock_setpriv(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_setsockopt(void);
int sock_setsockopt(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_shutdown(void);
int sock_shutdown(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_socket(void);
int sock_socket(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sockopt_copyin(void);
int sockopt_copyin(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sockopt_copyout(void);
int sockopt_copyout(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sockopt_direction(void);
int sockopt_direction(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sockopt_level(void);
int sockopt_level(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sockopt_name(void);
int sockopt_name(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sockopt_valsize(void);
int sockopt_valsize(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int kev_post_msg(void);
int kev_post_msg(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ctl_id_by_name(void);
int ctl_id_by_name(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ctl_name_by_id(void);
int ctl_name_by_id(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_allocate_extended(void);
int ifnet_allocate_extended(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_bandwidths(void);
int ifnet_bandwidths(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_clone_attach(void);
int ifnet_clone_attach(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_clone_detach(void);
int ifnet_clone_detach(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_dequeue(void);
int ifnet_dequeue(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_dequeue_multi(void);
int ifnet_dequeue_multi(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_dequeue_service_class(void);
int ifnet_dequeue_service_class(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_dequeue_service_class_multi(void);
int ifnet_dequeue_service_class_multi(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_enqueue(void);
int ifnet_enqueue(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_delegate(void);
int ifnet_get_delegate(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_inuse_address_list(void);
int ifnet_get_inuse_address_list(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_local_ports(void);
int ifnet_get_local_ports(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_local_ports_extended(void);
int ifnet_get_local_ports_extended(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_rcvq_maxlen(void);
int ifnet_get_rcvq_maxlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_sndq_len(void);
int ifnet_get_sndq_len(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_get_sndq_maxlen(void);
int ifnet_get_sndq_maxlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_idle_flags(void);
int ifnet_idle_flags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_inet6_defrouter_llreachinfo(void);
int ifnet_inet6_defrouter_llreachinfo(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_inet_defrouter_llreachinfo(void);
int ifnet_inet_defrouter_llreachinfo(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_input_extended(void);
int ifnet_input_extended(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_latencies(void);
int ifnet_latencies(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_link_quality(void);
int ifnet_link_quality(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_notice_master_elected(void);
int ifnet_notice_master_elected(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_notice_node_absence(void);
int ifnet_notice_node_absence(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_notice_node_presence(void);
int ifnet_notice_node_presence(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_poll_params(void);
int ifnet_poll_params(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_purge(void);
int ifnet_purge(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_report_issues(void);
int ifnet_report_issues(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_bandwidths(void);
int ifnet_set_bandwidths(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_idle_flags(void);
int ifnet_set_idle_flags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_latencies(void);
int ifnet_set_latencies(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_link_quality(void);
int ifnet_set_link_quality(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_output_sched_model(void);
int ifnet_set_output_sched_model(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_poll_params(void);
int ifnet_set_poll_params(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_rcvq_maxlen(void);
int ifnet_set_rcvq_maxlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_set_sndq_maxlen(void);
int ifnet_set_sndq_maxlen(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_start(void);
int ifnet_start(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_transmit_burst_end(void);
int ifnet_transmit_burst_end(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_transmit_burst_start(void);
int ifnet_transmit_burst_start(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_tx_compl_status(void);
int ifnet_tx_compl_status(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_flowid(void);
int ifnet_flowid(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_enable_output(void);
int ifnet_enable_output(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ifnet_disable_output(void);
int ifnet_disable_output(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int in6_localaddr(void);
int in6_localaddr(void)
{
	panic("stub called in a config with no networking");
	return 0; 
}

int in_localaddr(void);
int in_localaddr(void)
{
	panic("stub called in a config with no networking");
	return 0; 
}

int in6addr_local(void);
int in6addr_local(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int inaddr_local(void);
int inaddr_local(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int inp_clear_INP_INADDR_ANY(void);
int inp_clear_INP_INADDR_ANY(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ip_gre_output(void);
int ip_gre_output(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int m_cat(void);
int m_cat(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int m_free(void);
int m_free(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int m_freem(void);
int m_freem(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int m_get(void);
int m_get(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int m_gethdr(void);
int m_gethdr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int m_mtod(void);
int m_mtod(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int m_prepend_2(void);
int m_prepend_2(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int m_pullup(void);
int m_pullup(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int m_split(void);
int m_split(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int m_trailingspace(void);
int m_trailingspace(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_driver_scratch(void);
int mbuf_get_driver_scratch(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_priority(void);
int mbuf_get_priority(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_service_class(void);
int mbuf_get_service_class(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_service_class_index(void);
int mbuf_get_service_class_index(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_service_class_max_count(void);
int mbuf_get_service_class_max_count(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_traffic_class_index(void);
int mbuf_get_traffic_class_index(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_get_traffic_class_max_count(void);
int mbuf_get_traffic_class_max_count(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_is_service_class_privileged(void);
int mbuf_is_service_class_privileged(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mbuf_pkthdr_aux_flags(void);
int mbuf_pkthdr_aux_flags(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int mcl_to_paddr(void);
int mcl_to_paddr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int net_add_domain(void);
int net_add_domain(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int net_add_domain_old(void);
int net_add_domain_old(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int net_add_proto(void);
int net_add_proto(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int net_add_proto_old(void);
int net_add_proto_old(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int net_del_domain(void);
int net_del_domain(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int net_del_domain_old(void);
int net_del_domain_old(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int net_del_proto(void);
int net_del_proto(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int net_del_proto_old(void);
int net_del_proto_old(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pffinddomain(void);
int pffinddomain(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pffinddomain_old(void);
int pffinddomain_old(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pffindproto(void);
int pffindproto(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pffindproto_old(void);
int pffindproto_old(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_abort_notsupp(void);
int pru_abort_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_accept_notsupp(void);
int pru_accept_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_bind_notsupp(void);
int pru_bind_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_connect2_notsupp(void);
int pru_connect2_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_connect_notsupp(void);
int pru_connect_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_disconnect_notsupp(void);
int pru_disconnect_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_listen_notsupp(void);
int pru_listen_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_peeraddr_notsupp(void);
int pru_peeraddr_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_rcvd_notsupp(void);
int pru_rcvd_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_rcvoob_notsupp(void);
int pru_rcvoob_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_send_notsupp(void);
int pru_send_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_sense_null(void);
int pru_sense_null(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_shutdown_notsupp(void);
int pru_shutdown_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_sockaddr_notsupp(void);
int pru_sockaddr_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int pru_sopoll_notsupp(void);
int pru_sopoll_notsupp(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sbappendaddr(void);
int sbappendaddr(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sbappendrecord(void);
int sbappendrecord(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sbflush(void);
int sbflush(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sbspace(void);
int sbspace(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int soabort(void);
int soabort(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int socantrcvmore(void);
int socantrcvmore(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int socantsendmore(void);
int socantsendmore(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_getlistener(void);
int sock_getlistener(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_gettclassopt(void);
int sock_gettclassopt(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_release(void);
int sock_release(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_retain(void);
int sock_retain(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_settclassopt(void);
int sock_settclassopt(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_catchevents(void);
int sock_catchevents(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_setupcall(void);
int sock_setupcall(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sock_setupcalls(void);
int sock_setupcalls(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sodisconnect(void);
int sodisconnect(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sofree(void);
int sofree(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sofreelastref(void);
int sofreelastref(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int soisconnected(void);
int soisconnected(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int soisconnecting(void);
int soisconnecting(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int soisdisconnected(void);
int soisdisconnected(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int soisdisconnecting(void);
int soisdisconnecting(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sonewconn(void);
int sonewconn(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sooptcopyin(void);
int sooptcopyin(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sooptcopyout(void);
int sooptcopyout(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sopoll(void);
int sopoll(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int soreceive(void);
int soreceive(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int soreserve(void);
int soreserve(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sorwakeup(void);
int sorwakeup(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int sosend(void);
int sosend(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}



int utun_ctl_disable_crypto_dtls(void);
int utun_ctl_disable_crypto_dtls(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int utun_ctl_register_dtls(void);
int utun_ctl_register_dtls(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int utun_pkt_dtls_input(void);
int utun_pkt_dtls_input(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}


int dlil_resolve_multi(void);
int dlil_resolve_multi(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}


int inet_cksum_simple(void);
int inet_cksum_simple(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}


int arp_ip_handle_input(void);
int arp_ip_handle_input(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int arp_ifinit(void);
int arp_ifinit(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int arp_lookup_ip(void);
int arp_lookup_ip(void)  
{ 
	panic("stub called in a config with no networking");
	return 0; 
}

int ip_gre_register_input(void);
int ip_gre_register_input(void)
{
	panic("stub called in a config with no networking");
	return 0; 

}

#endif
