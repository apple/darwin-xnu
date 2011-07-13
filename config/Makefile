export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

ALL_SUBDIRS = 

INSTINC_SUBDIRS = 
INSTINC_SUBDIRS_I386 = 
INSTINC_SUBDIRS_X86_64 = 
INSTINC_SUBDIRS_ARM = 

EXPINC_SUBDIRS = 
EXPINC_SUBDIRS_I386 = 
EXPINC_SUBDIRS_X86_64 = 
EXPINC_SUBDIRS_ARM = 


COMP_SUBDIRS = 

INST_SUBDIRS =	


INSTALL_KEXT_PLIST_LIST= \
	System.kext/Info.plist \
	System.kext/PlugIns/Libkern.kext/Info.plist \
	System.kext/PlugIns/Mach.kext/Info.plist \
	System.kext/PlugIns/BSDKernel.kext/Info.plist \
	System.kext/PlugIns/MACFramework.kext/Info.plist \
	System.kext/PlugIns/IOKit.kext/Info.plist \
	System.kext/PlugIns/AppleNMI.kext/Info.plist \
	System.kext/PlugIns/ApplePlatformFamily.kext/Info.plist \
	System.kext/PlugIns/IONVRAMFamily.kext/Info.plist \
	System.kext/PlugIns/IOSystemManagement.kext/Info.plist \
	System.kext/PlugIns/Unsupported.kext/Info.plist \
	System.kext/PlugIns/Private.kext/Info.plist

INSTALL_KEXT_DIR = /System/Library/Extensions/


MD_SUPPORTED_KPI_FILENAME="SupportedKPIs-${ARCH_CONFIG_LC}.txt"
MI_SUPPORTED_KPI_FILENAME="SupportedKPIs-all-archs.txt"

ifneq ($(MACHINE_CONFIG), DEFAULT)
OBJPATH = $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)_$(MACHINE_CONFIG)
else
OBJPATH = $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)
endif

ifeq ($(ARCH_CONFIG),I386)
SUPPORT_SYSTEM60_KEXT	= 1
else
SUPPORT_SYSTEM60_KEXT	= 0
endif

ifeq ($(SUPPORT_SYSTEM60_KEXT),1)
INSTALL_KEXT_PLIST_LIST += \
	System.kext/PlugIns/System6.0.kext/Info.plist \
	System.kext/PlugIns/Libkern6.0.kext/Info.plist \
	System.kext/PlugIns/Mach6.0.kext/Info.plist \
	System.kext/PlugIns/BSDKernel6.0.kext/Info.plist \
	System.kext/PlugIns/IOKit6.0.kext/Info.plist
endif

SYMBOL_COMPONENT_LIST =	\
        System6.0	\
        BSDKernel	\
        IOKit		\
        Libkern		\
        Mach		\
        MACFramework	\
        Unsupported	\
        Private

SYMBOL_SET_BUILD = $(foreach set, $(SYMBOL_COMPONENT_LIST), $(OBJPATH)/$(set).symbolset)
SYMBOL_SET_FAT = $(foreach set, $(SYMBOL_COMPONENT_LIST), $(OBJROOT)/$(set).symbolset)

INSTALL_KEXT_PLISTS = $(addprefix $(DSTROOT)$(INSTALL_KEXT_DIR), $(INSTALL_KEXT_PLIST_LIST))

$(INSTALL_KEXT_PLISTS): $(DSTROOT)$(INSTALL_KEXT_DIR)% : $(SOURCE)/%
	@echo Install $< in $@
	$(_v)$(MKDIR) $(dir $@);				\
	$(RM) $(RMFLAGS) $@;					\
	$(INSTALL) $(DATA_INSTALL_FLAGS) $< $(dir $@)

$(OBJPATH)/allsymbols: $(OBJPATH)/mach_kernel
	$(_v)$(NM) -gj $< > $@

$(SYMBOL_SET_BUILD): $(OBJPATH)/%.symbolset :  %.exports %.$(ARCH_CONFIG_LC).exports $(OBJPATH)/allsymbols
	$(_v)if [ "$*" != System6.0 -o $(SUPPORT_SYSTEM60_KEXT) -eq 1 ]; then	\
		$(KEXT_CREATE_SYMBOL_SET) \
		$($(addsuffix $(ARCH_CONFIG),ARCH_FLAGS_ALL_)) \
		-import $(OBJPATH)/allsymbols \
		-export $*.exports \
		-export $*.$(ARCH_CONFIG_LC).exports \
		-output $@ $(_vstdout); \
	fi
	$(_v)if [ ! -e $@ ]; then	\
		printf "" > $@;		\
	fi

# When building the top-level install target for all architectures, aggregate the per-arch
# symbolsets for the primary machine configuration for each kernel/arch config
$(SYMBOL_SET_FAT): $(OBJROOT)/%.symbolset :
	$(_v)per_arch_symbolsets="";			\
	kernel_config=$(INSTALL_TYPE);			\
	machine_config=$(MACHINE_CONFIG);		\
	for arch_config in $(INSTALL_ARCHS);		\
	do						\
	if [ $${arch_config} = ARM ] ; then		\
		if [ $${machine_config} = DEFAULT ] ; then		\
			machine_config=$(DEFAULT_ARM_MACHINE_CONFIG);	\
		fi;							\
	fi;						\
	if [ $${machine_config} = DEFAULT ] ; then	\
		objpath=${OBJROOT}/$${kernel_config}_$${arch_config};	\
	else		\
		objpath=${OBJROOT}/$${kernel_config}_$${arch_config}_$${machine_config};	\
	fi;		\
	if [ -s "$${objpath}/$*.symbolset" ]; then			\
		per_arch_symbolsets="$${per_arch_symbolsets} $${objpath}/$*.symbolset";		\
	fi;		\
	done;		\
	if [ -n "$${per_arch_symbolsets}" ]; then			\
		$(LIPO) $${per_arch_symbolsets} -create -output $@;	\
	else		\
		printf "" > $@;						\
	fi

build_symbol_sets:	$(SYMBOL_SET_BUILD) $(OBJPATH)/allsymbols
	$(_v)$(KEXT_CREATE_SYMBOL_SET) \
		$($(addsuffix $(ARCH_CONFIG),ARCH_FLAGS_ALL_)) \
		$(foreach comp,$(filter-out System6.0 Private,$(SYMBOL_COMPONENT_LIST)), \
			-export $(SRCROOT)/$(COMPONENT)/$(comp).exports \
			-export $(SRCROOT)/$(COMPONENT)/$(comp).$(ARCH_CONFIG_LC).exports) \
		-import $(OBJPATH)/allsymbols \
		-output /dev/null $(_vstdout);
	$(_v)$(KEXT_CREATE_SYMBOL_SET) \
		$($(addsuffix $(ARCH_CONFIG),ARCH_FLAGS_ALL_)) \
		$(foreach comp,$(filter-out System6.0 Unsupported,$(SYMBOL_COMPONENT_LIST)), \
			-export $(SRCROOT)/$(COMPONENT)/$(comp).exports \
			-export $(SRCROOT)/$(COMPONENT)/$(comp).$(ARCH_CONFIG_LC).exports) \
		-import $(OBJPATH)/allsymbols \
		-output /dev/null $(_vstdout);
	$(_v) $(SRCROOT)/$(COMPONENT)/list_supported.sh $(SRCROOT)/$(COMPONENT) $(ARCH_CONFIG_LC) $(OBJPATH)/${MD_SUPPORTED_KPI_FILENAME};
	$(_v)if [ -n `echo $${ARCH_CONFIGS%%\ *} | grep -i  $(ARCH_CONFIG)` ]; \
	then \
		$(SRCROOT)/$(COMPONENT)/list_supported.sh $(SRCROOT)/$(COMPONENT) "ALL"  $(OBJROOT)/${MI_SUPPORTED_KPI_FILENAME}; \
	fi


install_symbol_sets:	$(SYMBOL_SET_FAT) $(SRCROOT)/config/MasterVersion $(INSTALL_KEXT_PLISTS)
	$(_v)if [ -s "$(OBJROOT)/System6.0.symbolset" -a $(SUPPORT_SYSTEM60_KEXT) -eq 1 ]; then	\
		install $(INSTALL_FLAGS) $(OBJROOT)/System6.0.symbolset    $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/System6.0.kext/kernel.6.0;	\
		install $(INSTALL_FLAGS) $(OBJROOT)/System6.0.symbolset    $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/Mach6.0.kext/Mach6.0;	\
		install $(INSTALL_FLAGS) $(OBJROOT)/System6.0.symbolset    $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/BSDKernel6.0.kext/BSDKernel6.0;	\
		install $(INSTALL_FLAGS) $(OBJROOT)/System6.0.symbolset    $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/Libkern6.0.kext/Libkern6.0;	\
		install $(INSTALL_FLAGS) $(OBJROOT)/System6.0.symbolset    $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/IOKit6.0.kext/IOKit6.0;	\
	fi
	$(_v)if [ -s "$(OBJROOT)/BSDKernel.symbolset" ]; then \
		install $(INSTALL_FLAGS) $(OBJROOT)/BSDKernel.symbolset    $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/BSDKernel.kext/BSDKernel;			\
		install $(INSTALL_FLAGS) $(OBJROOT)/IOKit.symbolset        $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/IOKit.kext/IOKit;				\
		install $(INSTALL_FLAGS) $(OBJROOT)/Libkern.symbolset      $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/Libkern.kext/Libkern;			\
		install $(INSTALL_FLAGS) $(OBJROOT)/Mach.symbolset         $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/Mach.kext/Mach;				\
		install $(INSTALL_FLAGS) $(OBJROOT)/MACFramework.symbolset $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/MACFramework.kext/MACFramework;		\
		install $(INSTALL_FLAGS) $(OBJROOT)/Unsupported.symbolset  $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/Unsupported.kext/Unsupported;		\
		install $(INSTALL_FLAGS) $(OBJROOT)/Private.symbolset      $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/Private.kext/Private;			\
	fi
	$(_v)$(NEWVERS) $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/AppleNMI.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/ApplePlatformFamily.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/BSDKernel.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/IOKit.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/IONVRAMFamily.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/IOSystemManagement.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/Libkern.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/Mach.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/MACFramework.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/Unsupported.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext/PlugIns/Private.kext/Info.plist;
	$(_v)$(MKDIR) $(DSTROOT)/$(KRESDIR);
	$(_v)install $(INSTALL_FLAGS) $(OBJPATH)/$(MD_SUPPORTED_KPI_FILENAME) $(DSTROOT)/$(KRESDIR);
	$(_v)if [ -n `echo $${ARCH_CONFIGS%%\ *} | grep -i  $(ARCH_CONFIG)` ]; then \
		install $(INSTALL_FLAGS) $(OBJROOT)/$(MI_SUPPORTED_KPI_FILENAME) $(DSTROOT)/$(KRESDIR); \
	fi
	$(_v)$(MKDIR) $(SYMROOT)
	$(_v)$(CP) -rf $(DSTROOT)/$(INSTALL_KEXT_DIR)/System.kext $(SYMROOT)

do_build_all:	build_symbol_sets

do_build_install:	install_symbol_sets 

EXPORTS_FILE_LIST = $(addprefix $(SOURCE)/,$(foreach set,$(SYMBOL_COMPONENT_LIST), $(set).exports $(set).$(ARCH_CONFIG_LC).exports))
EXPORTS_FILE_LIST_NOSYSTEM60 = $(addprefix $(SOURCE)/,$(foreach set, $(filter-out System6.0,$(SYMBOL_COMPONENT_LIST)), $(set).exports $(set).$(ARCH_CONFIG_LC).exports))

# Does not include "whole-kernel" clients
build_mach_kernel_exports:
	$(_v)if [ $(SUPPORT_SYSTEM60_KEXT) -eq 1 ]; then \
		$(SOURCE)/generate_linker_exports.sh $(OBJPATH)/kernel-kpi.exp \
		 	 $(EXPORTS_FILE_LIST) || exit 1; \
	else \
		$(SOURCE)/generate_linker_exports.sh $(OBJPATH)/kernel-kpi.exp \
		 	 $(EXPORTS_FILE_LIST_NOSYSTEM60) || exit 1; \
	fi;

include $(MakeInc_rule)
include $(MakeInc_dir)
