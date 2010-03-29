export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \

INSTINC_SUBDIRS_PPC = \

INSTINC_SUBDIRS_I386 = \

EXPINC_SUBDIRS = \

EXPINC_SUBDIRS_PPC = \

EXPINC_SUBDIRS_I386 = \

DATAFILES= \
	bpf.h dlil.h \
	ethernet.h if.h if_arp.h \
	if_dl.h if_llc.h if_media.h if_mib.h \
	if_types.h if_var.h \
	kext_net.h ndrv.h pfkeyv2.h \
	route.h

KERNELFILES= \
	kpi_interface.h kpi_interfacefilter.h kpi_protocol.h \
	if_ether.h init.h radix.h

PRIVATE_DATAFILES = \
	if_atm.h if_vlan_var.h if_ppp.h firewire.h \
	ppp_defs.h radix.h if_bond_var.h lacp.h ndrv_var.h \
	raw_cb.h etherdefs.h iso88025.h if_pflog.h pfvar.h \
	if_bridgevar.h

PRIVATE_KERNELFILES = ${KERNELFILES} \
	bpfdesc.h dlil_pvt.h ppp_comp.h \
	zlib.h bpf_compat.h net_osdep.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = net

EXPORT_MI_LIST	= ${INSTALL_MI_LIST} ${KERNELFILES}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${INSTALL_MI_LCL_LIST} ${PRIVATE_KERNELFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)
