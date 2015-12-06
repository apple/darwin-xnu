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
	netinet \
	netinet6 \
	netkey \
	nfs \
	security \
	sys \
	uuid \
	vfs

INSTINC_SUBDIRS_X86_64 = \
	i386 \
	crypto

INSTINC_SUBDIRS_X86_64H = \
	i386 \
	crypto

INSTINC_SUBDIRS_ARM = \
	arm 

INSTINC_SUBDIRS_ARM64 = \
	arm

EXPINC_SUBDIRS = \
	bsm \
	dev \
	hfs \
	libkern \
	machine \
	miscfs \
	net \
	netinet \
	netinet6 \
	netkey \
	security \
	sys \
	uuid \
	vfs \
	vm

EXPINC_SUBDIRS_X86_64 = \
	i386 

EXPINC_SUBDIRS_X86_64H = \
	i386 

EXPINC_SUBDIRS_ARM = \
	arm 

EXPINC_SUBDIRS_ARM64 = \
	arm

COMP_SUBDIRS = 	\
	conf

INSTTEXTFILES_SUBDIRS =	\
	dev \
	kern \
	man

include $(MakeInc_rule)
include $(MakeInc_dir)
