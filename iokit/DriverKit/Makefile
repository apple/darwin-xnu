export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

IIG_INCFLAGS = -I$(SRCROOT)/iokit -I$(SRCROOT)/osfmk -I$(SRCROOT)/bsd -I$(OBJROOT)/bsd $(INCFLAGS_EXTERN)
OTHER_IIG_CFLAGS = $(IIG_INCFLAGS) -isysroot $(SDKROOT) -x c++ -std=gnu++1z -D__IIG=1 -DDRIVERKIT_PRIVATE=1 $(DEPLOYMENT_TARGET_DEFINES) $($(addsuffix $(CURRENT_ARCH_CONFIG),ARCH_FLAGS_))

INCDIR = $(FRAMEDIR)/$(DKIT_INCDIR)
DRIVERKITINCDIR = $(DRIVERKITFRAMEDIR)/$(DRIVERKIT_DKIT_INCDIR)
LCLDIR = $(FRAMEDIR)/$(DKIT_PINCDIR)

include $(MakeInc_cmd)
include $(MakeInc_def)

ALL_DEFS = $(notdir $(wildcard $(SOURCE)*.iig))
ALL_HDRS = $(notdir $(wildcard $(SOURCE)*.h))

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}

INSTALL_MI_DIR = .

EXPORT_MI_DIR = DriverKit

GENERATED_HEADERS = $(patsubst %.iig,%.h,$(ALL_DEFS))

GENERATED_IMPL = $(patsubst %.iig,%.iig.cpp,$(ALL_DEFS))

INSTALL_MI_LIST = $(ALL_DEFS)
INSTALL_DRIVERKIT_MI_LIST = $(ALL_DEFS)

OTHER_HEADERS = IOTypes.h IOReturn.h IORPC.h IOKitKeys.h

EXPORT_MI_GEN_LIST = $(GENERATED_HEADERS)  $(OTHER_HEADERS)
INSTALL_MI_GEN_LIST = $(GENERATED_HEADERS)  $(OTHER_HEADERS)
INSTALL_DRIVERKIT_MI_GEN_LIST = $(GENERATED_HEADERS)  $(OTHER_HEADERS)
INSTALL_KF_MI_GEN_LIST = $(GENERATED_HEADERS)  $(OTHER_HEADERS)

COMP_FILES = ${GENERATED_HEADERS} $(GENERATED_IMPL)

$(GENERATED_HEADERS) : \
	%.h : %.iig
	$(IIG) --def $< --header $@ --impl $(patsubst %.h,%.iig.cpp,$@) --framework-name DriverKit ${OTHER_IIG_FLAGS} -- ${OTHER_IIG_CFLAGS}

$(GENERATED_IMPL) : $(GENERATED_HEADERS)

do_build_all:: $(COMP_FILES)

include $(MakeInc_rule)
include $(MakeInc_dir)
