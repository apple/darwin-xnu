export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS =
INSTINC_SUBDIRS_PPC = ${INSTINC_SUBDIRS}
INSTINC_SUBDIRS_I386 = ${INSTINC_SUBDIRS}

EXPINC_SUBDIRS = mach 
EXPINC_SUBDIRS_PPC = ${EXPINC_SUBDIRS} ppc
EXPINC_SUBDIRS_I386 = ${EXPINC_SUBDIRS} i386

INSTALL_MI_LIST	= 

INSTALL_MI_DIR = libsa

EXPORT_MI_LIST	= mkext.h setjmp.h stdlib.h unistd.h

EXPORT_MI_DIR = libsa


include $(MakeInc_rule)
include $(MakeInc_dir)


