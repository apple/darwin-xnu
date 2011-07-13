export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	bsm \
	crypto \
	dev \
	hfs \
	libkern \
	machine \
	miscfs \
	net \
	netat \
	netinet \
	netinet6 \
	netkey \
	nfs \
	security \
	sys \
	uuid \
	vfs

INSTINC_SUBDIRS_I386 = \
	i386 \
	crypto

INSTINC_SUBDIRS_X86_64 = \
	i386 \
	crypto

INSTINC_SUBDIRS_ARM = \
	arm 

EXPINC_SUBDIRS = \
	bsm \
	crypto \
	dev \
	hfs \
	libkern \
	machine \
	miscfs \
	net \
	netat \
	netinet \
	netinet6 \
	netkey \
	nfs \
	security \
	sys \
	uuid \
	vfs \
	vm

EXPINC_SUBDIRS_I386 = \
	i386 

EXPINC_SUBDIRS_X86_64 = \
	i386 

EXPINC_SUBDIRS_ARM = \
	arm 

SETUP_SUBDIRS =

COMP_SUBDIRS = 	\
	conf

INST_SUBDIRS =	\
	kern

INSTMAN_SUBDIRS = \
	man


include $(MakeInc_rule)
include $(MakeInc_dir)
