export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
          OSArray.h \
          OSBoolean.h \
          OSCollection.h \
          OSCollectionIterator.h \
          OSContainers.h \
          OSCPPDebug.h \
          OSData.h \
          OSDictionary.h \
          OSEndianTypes.h \
          OSIterator.h \
          OSKext.h \
          OSLib.h \
          OSMetaClass.h \
          OSNumber.h \
          OSObject.h \
          OSOrderedSet.h \
          OSSerialize.h \
          OSSet.h \
          OSString.h \
          OSSymbol.h \
          OSUnserialize.h

INSTALL_MI_LIST	=

INSTALL_MI_DIR = libkern/c++

EXPORT_MI_LIST	= ${DATAFILES}

EXPORT_MI_DIR = libkern/c++

include $(MakeInc_rule)
include $(MakeInc_dir)


