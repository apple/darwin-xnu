export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

ALL_SUBDIRS = 

INSTINC_SUBDIRS = 

INSTINC_SUBDIRS_PPC = 

INSTINC_SUBDIRS_I386 = 

EXPINC_SUBDIRS = 

EXPINC_SUBDIRS_PPC =  

EXPINC_SUBDIRS_I386 = 

COMP_SUBDIRS = 

INST_SUBDIRS =	


INSTALL_DATA_LIST= \
	IPFirewall.kext/Info.plist \
	System.kext/Info.plist \
	System.kext/PlugIns/Libkern.kext/Info.plist \
	System.kext/PlugIns/Mach.kext/Info.plist \
	System.kext/PlugIns/BSDKernel.kext/Info.plist \
	System.kext/PlugIns/IOKit.kext/Info.plist \
	System.kext/PlugIns/AppleNMI.kext/Info.plist \
	System.kext/PlugIns/ApplePlatformFamily.kext/Info.plist \
	System.kext/PlugIns/IONVRAMFamily.kext/Info.plist \
	System.kext/PlugIns/IOSystemManagement.kext/Info.plist \
	System.kext/PlugIns/Unsupported.kext/Info.plist \
	\
	System.kext/PlugIns/System6.0.kext/Info.plist \
	System.kext/PlugIns/Libkern6.0.kext/Info.plist \
	System.kext/PlugIns/Mach6.0.kext/Info.plist \
	System.kext/PlugIns/BSDKernel6.0.kext/Info.plist \
	System.kext/PlugIns/IOKit6.0.kext/Info.plist \

INSTALL_DATA_DIR= \
	/System/Library/Extensions/

INSTMAN_SUBDIRS = 

#

KEXT_CREATE_SYMBOL_SET = /usr/local/bin/kextsymboltool
NEWVERS = $(SRCROOT)/config/newvers.pl

SYMBOL_COMPONENT_LIST =	\
        System6.0	\
        BSDKernel	\
        IOKit		\
        Libkern	\
        Mach	\
	Unsupported

SYMBOL_SET_BUILD = $(foreach set, $(SYMBOL_COMPONENT_LIST), $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/$(set).symbolset)
SYMBOL_SET_FAT = $(foreach set, $(SYMBOL_COMPONENT_LIST), $(OBJROOT)/$(set).symbolset)

## .SUFFIXES: .symbolset .symbollist

$(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/allsymbols: $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/mach_kernel
	nm -gj $< > $@

$(SYMBOL_SET_BUILD): $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/%.symbolset :  %.exports %.$(ARCH_CONFIG_LC).exports $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/allsymbols
	$(KEXT_CREATE_SYMBOL_SET) \
		-arch $(ARCH_CONFIG_LC) \
		-import $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/allsymbols \
		-export $*.exports \
		-export $*.$(ARCH_CONFIG_LC).exports \
		-output $@;

$(SYMBOL_SET_FAT): $(OBJROOT)/%.symbolset : $(foreach arch, $(INSTALL_ARCHS), $(OBJROOT)/$(KERNEL_CONFIG)_$(arch)/%.symbolset)
	$(LIPO) $(foreach arch, $(INSTALL_ARCHS), $(OBJROOT)/$(KERNEL_CONFIG)_$(arch)/$*.symbolset) -create -output $@;


build_symbol_sets:	$(SYMBOL_SET_BUILD)
	$(KEXT_CREATE_SYMBOL_SET) \
		-arch $(ARCH_CONFIG_LC) \
		-import $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/allsymbols \
		-export $(SRCROOT)/$(COMPONENT)/Libkern.exports \
		-export $(SRCROOT)/$(COMPONENT)/Libkern.$(ARCH_CONFIG_LC).exports \
		-export $(SRCROOT)/$(COMPONENT)/Mach.exports \
		-export $(SRCROOT)/$(COMPONENT)/Mach.$(ARCH_CONFIG_LC).exports \
		-export $(SRCROOT)/$(COMPONENT)/IOKit.exports \
		-export $(SRCROOT)/$(COMPONENT)/IOKit.$(ARCH_CONFIG_LC).exports \
		-export $(SRCROOT)/$(COMPONENT)/BSDKernel.exports \
		-export $(SRCROOT)/$(COMPONENT)/BSDKernel.$(ARCH_CONFIG_LC).exports \
		-export $(SRCROOT)/$(COMPONENT)/Unsupported.exports \
		-export $(SRCROOT)/$(COMPONENT)/Unsupported.$(ARCH_CONFIG_LC).exports \
		-output /dev/null;

install_symbol_sets:	$(SYMBOL_SET_FAT) $(SRCROOT)/config/MasterVersion
	install $(INSTALL_FLAGS) $(OBJROOT)/System6.0.symbolset $(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/System6.0.kext/kernel.6.0;
	install $(INSTALL_FLAGS) $(OBJROOT)/BSDKernel.symbolset $(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/BSDKernel.kext/BSDKernel;
	install $(INSTALL_FLAGS) $(OBJROOT)/IOKit.symbolset     $(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/IOKit.kext/IOKit;
	install $(INSTALL_FLAGS) $(OBJROOT)/Libkern.symbolset   $(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/Libkern.kext/Libkern;
	install $(INSTALL_FLAGS) $(OBJROOT)/Mach.symbolset      $(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/Mach.kext/Mach;
	install $(INSTALL_FLAGS) $(OBJROOT)/Unsupported.symbolset      $(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/Unsupported.kext/Unsupported;
	$(NEWVERS) $(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/AppleNMI.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/ApplePlatformFamily.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/BSDKernel.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/IOKit.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/IONVRAMFamily.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/IOSystemManagement.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/Libkern.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/Mach.kext/Info.plist \
		$(DSTROOT)/$(INSTALL_DATA_DIR)/System.kext/PlugIns/Unsupported.kext/Info.plist

do_build_all:	build_symbol_sets

do_build_install:	install_symbol_sets

include $(MakeInc_rule)
include $(MakeInc_dir)
