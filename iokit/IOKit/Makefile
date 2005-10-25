export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

IOKIT_FRAMEDIR = $(FRAMEDIR)/IOKit.framework/Versions/A
export INCDIR = $(IOKIT_FRAMEDIR)/Headers
export LCLDIR = $(IOKIT_FRAMEDIR)/PrivateHeaders

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	nvram \
	platform \
	power \
	pwr_mgt \
	rtc \
	system_management

INSTINC_SUBDIRS_PPC = \
	ppc

INSTINC_SUBDIRS_I386 = \
	i386

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}
EXPINC_SUBDIRS_PPC = ${INSTINC_SUBDIRS_PPC}
EXPINC_SUBDIRS_I386 = ${INSTINC_SUBDIRS_I386}

NOT_EXPORT_HEADERS = 

NOT_KF_MI_HEADERS  = $(NOT_EXPORT_HEADERS) IOKitKeysPrivate.h IOCPU.h IOHibernatePrivate.h IOPolledInterface.h

NOT_LOCAL_HEADERS = 

ALL_HEADERS = $(shell (cd $(SOURCE); echo *.h))

INSTALL_MI_LIST	= IOBSD.h IOKitKeys.h IOKitServer.h IOReturn.h\
		  IOSharedLock.h IOTypes.h OSMessageNotification.h\
		  IODataQueueShared.h IOMessage.h
                  
INSTALL_MI_LCL_LIST = IOKitKeysPrivate.h IOHibernatePrivate.h

INSTALL_MI_DIR = .

EXPORT_MI_LIST	= $(filter-out $(NOT_EXPORT_HEADERS), $(ALL_HEADERS))

EXPORT_MI_DIR = IOKit

INSTALL_KF_MI_LIST = $(filter-out $(NOT_KF_MI_HEADERS), $(ALL_HEADERS))

include $(MakeInc_rule)
include $(MakeInc_dir)
