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

DATAFILES = \
	bootp.h icmp6.h if_ether.h icmp_var.h \
	igmp.h igmp_var.h in.h in_pcb.h \
	in_systm.h in_var.h ip.h ip6.h \
	ip_fw.h ip_fw2.h \
	ip_icmp.h ip_mroute.h ip_var.h tcp.h \
	tcp_fsm.h tcp_seq.h tcp_timer.h tcp_var.h \
	tcpip.h udp.h udp_var.h

KERNELFILES = \
	kpi_ipfilter.h in_arp.h

PRIVATE_DATAFILES = \
	if_fddi.h if_atm.h ip_dummynet.h \
	tcp_debug.h \
	in_gif.h ip_compat.h ip_edgehole.h

PRIVATE_KERNELFILES = ${KERNELFILES} \
	ip_ecn.h ip_encap.h ip_flow.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = netinet

EXPORT_MI_LIST	= ${DATAFILES} ${KERNELFILES}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${INSTALL_MI_LCL_LIST} ${PRIVATE_KERNELFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)


