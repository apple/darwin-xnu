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
	bpf.h bpf_compat.h bpfdesc.h dlil.h dlil_pvt.h \
	etherdefs.h ethernet.h if.h if_arp.h \
	if_dl.h if_llc.h if_media.h if_mib.h \
	if_slvar.h \
	if_types.h if_var.h iso88025.h \
	kext_net.h ndrv.h net_osdep.h netisr.h pfkeyv2.h \
	radix.h raw_cb.h route.h slcompress.h slip.h

PRIVATE_DATAFILES = \
	ndrv_var.h zlib.h if_pppvar.h if_sppp.h ppp_comp.h if_atm.h \
	if_tun.h if_vlan_var.h if_ppp.h firewire.h ppp_defs.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = net

EXPORT_MI_LIST	= ${INSTALL_MI_LIST}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_MI_LCL_KERN_LIST = ${PRIVATE_DATAFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)
