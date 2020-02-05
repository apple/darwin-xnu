export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	ah.h ipsec.h \
	esp.h in6.h ipcomp.h raw_ip6.h \
	scope6_var.h in6_var.h nd6.h

PRIVATE_DATAFILES = \
	in6.h \
	in6_pcb.h \
	in6_var.h \
	ip6_fw.h \
	ip6_var.h \
	mld6_var.h \
	nd6.h \
	scope6_var.h

PRIVATE_KERNELFILES = \
	ah6.h esp6.h esp_rijndael.h esp_chachapoly.h \
	in6_gif.h in6_ifattach.h ip6_ecn.h ip6protosw.h \
	ipsec6.h tcp6_var.h udp6_var.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = netinet6

EXPORT_MI_LIST = ${DATAFILES}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = $(sort ${DATAFILES} ${PRIVATE_DATAFILES} ${PRIVATE_KERNELFILES})

include $(MakeInc_rule)
include $(MakeInc_dir)
