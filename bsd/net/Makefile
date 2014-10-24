export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	altq classq pktsched

DATAFILES= \
	bpf.h dlil.h \
	ethernet.h if.h if_arp.h \
	if_dl.h if_llc.h if_media.h if_mib.h \
	if_types.h if_var.h \
	if_utun.h \
	kext_net.h ndrv.h pfkeyv2.h \
	route.h

KERNELFILES= \
	kpi_interface.h kpi_interfacefilter.h kpi_protocol.h \
	if_ether.h init.h radix.h

PRIVATE_DATAFILES = \
	if_vlan_var.h if_ppp.h firewire.h \
	ppp_defs.h radix.h if_bond_var.h if_bond_internal.h lacp.h ndrv_var.h \
	netsrc.h raw_cb.h etherdefs.h if_pflog.h pfvar.h \
	if_bridgevar.h ntstat.h iptap.h if_llreach.h \
	if_utun_crypto.h if_utun_crypto_ipsec.h if_utun_crypto_dtls.h \
	pktap.h if_ipsec.h necp.h content_filter.h packet_mangler.h

PRIVATE_KERNELFILES = $(filter-out radix.h,${KERNELFILES}) \
	bpfdesc.h ppp_comp.h \
	zlib.h bpf_compat.h net_osdep.h \
	flowadv.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = net

EXPORT_MI_LIST	= ${INSTALL_MI_LIST} ${KERNELFILES}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${INSTALL_MI_LCL_LIST} ${PRIVATE_KERNELFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)
