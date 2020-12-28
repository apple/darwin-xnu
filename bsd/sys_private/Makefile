# This private directory is necessary for BSD headers bound for
# `/usr/local/include/sys/` and the System framework.

export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTALL_MI_DIR = sys
INCDIR = $(SDKHEADERSROOT)/usr/local/include
DRIVERKITINCDIR = $(DRIVERKITSDKHEADERSROOT)/usr/local/include

# Installs header files for Apple internal use in
#     $(DSTROOT)/usr/local/include/sys

INSTALL_MI_LIST = \
	kdebug_private.h

INSTALL_DRIVERKIT_MI_LIST = \
	kdebug_private.h

# Installs header files for Apple internal use in
#     $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders/sys

INSTALL_MI_LCL_LIST = \
	kdebug_private.h

EXPORT_MI_DIR = sys

EXPORT_MI_LIST = \
	kdebug_private.h

include $(MakeInc_rule)
include $(MakeInc_dir)
