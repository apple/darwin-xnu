export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

IOKIT_INCVERS = A
IOKIT_INCFRAME = $(FRAMEDIR)/IOKit.framework
IOKIT_INCDIR = $(IOKIT_INCFRAME)/Versions/$(IOKIT_INCVERS)/Headers
IOKIT_PINCDIR = $(IOKIT_INCFRAME)/Versions/$(IOKIT_INCVERS)/PrivateHeaders

INCDIR = $(IOKIT_INCDIR)
LCLDIR = $(IOKIT_PINCDIR)

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	nvram \
	platform \
	power \
	pwr_mgt \
	rtc \
	system_management


EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}

# By default, everything in xnu/iokit/IOKit gets installed into
# Kernel.framework/Headers/IOKit AND Kernel.framework/PrivateHeaders/IOKit.
# This is so the files with #ifdef ...PRIVATE portions can be processed.
# xnu/README documents the INSTALL* and EXPORT_MI_DIR lists.
ALL_HEADERS = $(shell (cd $(SOURCE); echo *.h))

# Do not install these headers (anywhere).
NOT_EXPORT_HEADERS = IOInterruptAccountingPrivate.h

# Install these only in Kernel.framework's PrivateHeaders (not Headers).
NOT_KF_MI_HEADERS  = $(NOT_EXPORT_HEADERS)			\
		     IOKitKeysPrivate.h IOCPU.h			\
		     IOHibernatePrivate.h IOPolledInterface.h	\
		     IOCommandQueue.h IOLocksPrivate.h		\
		     IOSyncer.h AppleKeyStoreInterface.h	\
		     IOStatistics.h IOStatisticsPrivate.h	\
		     IOKernelReporters.h

# These should be additionally installed in IOKit.framework's public Headers
INSTALL_MI_LIST	= IOBSD.h IOKitKeys.h IOKitServer.h IOReturn.h\
		  IOSharedLock.h IOTypes.h OSMessageNotification.h\
		  IODataQueueShared.h IOMessage.h IOInterruptAccounting.h\

# These should be additionally installed in IOKit.framework's PrivateHeaders
INSTALL_MI_LCL_LIST = IOKitKeysPrivate.h IOHibernatePrivate.h \
					  IOLocksPrivate.h IOStatistics.h \
					  AppleKeyStoreInterface.h  \
					  IOReportTypes.h IOKernelReportStructs.h \
					  IOReportMacros.h

INSTALL_MI_DIR = .

EXPORT_MI_LIST	= $(filter-out $(NOT_EXPORT_HEADERS), $(ALL_HEADERS))

EXPORT_MI_DIR = IOKit

INSTALL_KF_MI_LIST = $(filter-out $(NOT_KF_MI_HEADERS), $(ALL_HEADERS))

include $(MakeInc_rule)
include $(MakeInc_dir)
