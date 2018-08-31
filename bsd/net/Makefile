export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	altq classq pktsched

DATAFILES= \
	bpf.h \
	dlil.h \
	ethernet.h \
	if.h \
	if_arp.h \
	if_dl.h \
	if_llc.h \
	if_media.h \
	if_mib.h \
	if_types.h \
	if_var.h \
	if_utun.h \
	kext_net.h \
	ndrv.h \
	pfkeyv2.h \
	route.h	\
	net_kev.h

KERNELFILES= \
	kpi_interface.h kpi_interfacefilter.h kpi_protocol.h \
	if_ether.h init.h radix.h

PRIVATE_DATAFILES = \
	bpf.h \
	content_filter.h \
	etherdefs.h \
	firewire.h \
	if.h \
	if_bond_var.h \
	if_bond_internal.h \
	if_bridgevar.h \
	if_ipsec.h \
	if_llreach.h \
	if_media.h \
	if_mib.h \
	if_pflog.h \
	if_ports_used.h \
	if_ppp.h \
	if_utun.h \
	if_var.h \
	if_vlan_var.h \
	if_fake_var.h \
	iptap.h \
	lacp.h \
	ndrv_var.h \
	necp.h \
	net_api_stats.h \
	netsrc.h \
	network_agent.h \
	ntstat.h \
	packet_mangler.h \
	pfkeyv2.h \
	pfvar.h \
	pktap.h \
	ppp_defs.h \
	radix.h \
	raw_cb.h \
	route.h \
	net_perf.h \
	net_kev.h

PRIVATE_KERNELFILES = $(filter-out radix.h,${KERNELFILES}) \
	bpfdesc.h ppp_comp.h \
	zlib.h bpf_compat.h net_osdep.h \
	flowadv.h net_perf.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = net

EXPORT_MI_LIST	= ${INSTALL_MI_LIST} ${KERNELFILES}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = $(sort ${DATAFILES} ${PRIVATE_DATAFILES} ${PRIVATE_KERNELFILES})

include $(MakeInc_rule)
include $(MakeInc_dir)
