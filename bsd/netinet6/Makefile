export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	ah.h ipsec.h pim6.h  \
	esp.h in6.h ipcomp.h raw_ip6.h \
	in6_var.h ip6_mroute.h nd6.h

PRIVATE_DATAFILES = \
	in6_pcb.h ip6_var.h pim6_var.h mld6_var.h ip6_fw.h

PRIVATE_KERNELFILES = \
	ah6.h esp6.h esp_rijndael.h in6_gif.h in6_ifattach.h \
	ip6_ecn.h ip6protosw.h ipcomp6.h ipsec6.h \
	scope6_var.h tcp6_var.h udp6_var.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = netinet6

EXPORT_MI_LIST	= ${DATAFILES}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${INSTALL_MI_LCL_LIST} ${PRIVATE_KERNELFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)
