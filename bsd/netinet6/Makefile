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
	ah.h             esp_rijndael.h   in6_ifattach.h   ip6.h \
        ip6_var.h	 ipsec.h          pim6.h           tcp6_var.h \
	ah6.h            icmp6.h          in6_pcb.h        ip6_ecn.h \
        ip6protosw.h     ipsec6.h         pim6_var.h       udp6_var.h \
	esp.h            in6.h            in6_prefix.h     \
        ipcomp.h         mld6_var.h       raw_ip6.h	   esp6.h \
        in6_gif.h        in6_var.h        ip6_mroute.h     ipcomp6.h \
	nd6.h            scope6_var.h     ip6_fw.h



INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = netinet6

EXPORT_MI_LIST	= ${DATAFILES}

EXPORT_MI_DIR = netinet6

PRIVATE_DATAFILES = \
	ip6_fw.h

INSTALL_MI_LCL_KERN_LIST = ${PRIVATE_DATAFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)


