export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

IOKIT_INCVERS = A
IOKIT_INCFRAME = $(FRAMEDIR)/IOKit.framework
IOKIT_INCDIR = $(IOKIT_INCFRAME)/Versions/$(IOKIT_INCVERS)/Headers
IOKIT_PINCDIR = $(IOKIT_INCFRAME)/Versions/$(IOKIT_INCVERS)/PrivateHeaders

export INCDIR = $(IOKIT_INCDIR)
export LCLDIR = $(IOKIT_PINCDIR)

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	nvram \
	platform \
	power \
	pwr_mgt \
	rtc \
	system_management

INSTINC_SUBDIRS_I386 = 

INSTINC_SUBDIRS_X86_64 = 


EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}
EXPINC_SUBDIRS_I386 = ${INSTINC_SUBDIRS_I386}
EXPINC_SUBDIRS_X86_64 = ${INSTINC_SUBDIRS_X86_64}


NOT_EXPORT_HEADERS = 

NOT_KF_MI_HEADERS  = $(NOT_EXPORT_HEADERS)			\
		     IOKitKeysPrivate.h IOCPU.h			\
		     IOHibernatePrivate.h IOPolledInterface.h	\
		     IOCommandQueue.h IOLocksPrivate.h 		\
		     IOSyncer.h AppleKeyStoreInterface.h	\
		     IOStatistics.h IOStatisticsPrivate.h

NOT_LOCAL_HEADERS = 

ALL_HEADERS = $(shell (cd $(SOURCE); echo *.h))

INSTALL_MI_LIST	= IOBSD.h IOKitKeys.h IOKitServer.h IOReturn.h\
		  IOSharedLock.h IOTypes.h OSMessageNotification.h\
		  IODataQueueShared.h IOMessage.h
                  
INSTALL_MI_LCL_LIST = IOKitKeysPrivate.h IOHibernatePrivate.h IOLocksPrivate.h IOStatistics.h AppleKeyStoreInterface.h

INSTALL_MI_DIR = .

EXPORT_MI_LIST	= $(filter-out $(NOT_EXPORT_HEADERS), $(ALL_HEADERS))

EXPORT_MI_DIR = IOKit

INSTALL_KF_MI_LIST = $(filter-out $(NOT_KF_MI_HEADERS), $(ALL_HEADERS))

include $(MakeInc_rule)
include $(MakeInc_dir)
