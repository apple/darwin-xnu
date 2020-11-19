export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
          OSAllocation.h \
          OSArray.h \
          OSBoolean.h \
          OSBoundedArray.h \
          OSBoundedArrayRef.h \
          OSBoundedPtr.h \
          OSBoundedPtrFwd.h \
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
          OSPtr.h \
          OSSharedPtr.h \
          intrusive_shared_ptr.h \
          OSSerialize.h \
          OSSet.h \
          OSString.h \
          OSSymbol.h \
          OSUnserialize.h \
          bounded_array.h \
          bounded_array_ref.h \
          bounded_ptr.h \
          bounded_ptr_fwd.h \
          safe_allocation.h

INSTALL_MI_LIST	=

INSTALL_MI_DIR = libkern/c++

EXPORT_MI_LIST	= ${DATAFILES}

EXPORT_MI_DIR = libkern/c++

include $(MakeInc_rule)
include $(MakeInc_dir)
