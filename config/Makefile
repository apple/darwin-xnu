export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)


MD_SUPPORTED_KPI_FILENAME = SupportedKPIs-${CURRENT_ARCH_CONFIG_LC}.txt
MI_SUPPORTED_KPI_FILENAME = SupportedKPIs-all-archs.txt

INSTALL_KEXT_DIR = $(DSTROOT)$(INSTALL_EXTENSIONS_DIR)

KEXT_PLIST_LIST = \
	System.kext/Info.plist \
	System.kext/PlugIns/AppleNMI.kext/Info.plist \
	System.kext/PlugIns/ApplePlatformFamily.kext/Info.plist \
	System.kext/PlugIns/IONVRAMFamily.kext/Info.plist \
	System.kext/PlugIns/IOSystemManagement.kext/Info.plist

SYMBOL_COMPONENT_LIST =	\
        BSDKernel	\
        IOKit		\
        Libkern		\
        Mach		\
        MACFramework	\
        Unsupported	\
        Private

KEXT_MACHO_LIST = $(foreach symbolset,$(filter-out Dummy,$(SYMBOL_COMPONENT_LIST)),System.kext/PlugIns/$(symbolset).kext/$(symbolset))
KEXT_PLIST_LIST += $(foreach symbolset,$(filter-out Dummy,$(SYMBOL_COMPONENT_LIST)),System.kext/PlugIns/$(symbolset).kext/Info.plist)

SYMROOT_INSTALL_KEXT_MACHO_FILES = $(addprefix $(SYMROOT)/,$(KEXT_MACHO_LIST))
DSTROOT_INSTALL_KEXT_MACHO_FILES = $(addprefix $(INSTALL_KEXT_DIR)/,$(KEXT_MACHO_LIST))

SYMROOT_INSTALL_KEXT_PLISTS = $(addprefix $(SYMROOT)/,$(KEXT_PLIST_LIST))
DSTROOT_INSTALL_KEXT_PLISTS = $(addprefix $(INSTALL_KEXT_DIR)/,$(KEXT_PLIST_LIST))

EXPORTS_FILES = $(foreach symbolset,$(SYMBOL_COMPONENT_LIST),$(symbolset).exports $(symbolset).$(CURRENT_ARCH_CONFIG_LC).exports) Unused.exports

SYMBOL_SET_BUILD = $(foreach symbolset, $(SYMBOL_COMPONENT_LIST), $(OBJPATH)/$(symbolset).symbolset)

$(OBJPATH)/allsymbols: $(OBJPATH)/mach_kernel
	$(_v)$(NM) -gj $< > $@

$(SYMBOL_SET_BUILD): $(OBJPATH)/%.symbolset :  %.exports %.$(CURRENT_ARCH_CONFIG_LC).exports $(OBJPATH)/allsymbols
	@echo SYMBOLSET $* "($(CURRENT_ARCH_CONFIG_LC))"
	$(_v)$(KEXT_CREATE_SYMBOL_SET)					\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))			\
		-import $(OBJPATH)/allsymbols				\
		-export $(SOURCE)/$*.exports				\
		-export $(SOURCE)/$*.$(CURRENT_ARCH_CONFIG_LC).exports	\
		-output $@ $(_vstdout)

.PHONY: check_all_exports

check_all_exports: $(OBJPATH)/allsymbols
	$(_v)$(KEXT_CREATE_SYMBOL_SET)					\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))			\
		-import $(OBJPATH)/allsymbols				\
		$(foreach symbolset,$(filter-out Private,$(SYMBOL_COMPONENT_LIST)),	\
			-export $(SOURCE)/$(symbolset).exports		\
			-export $(SOURCE)/$(symbolset).$(CURRENT_ARCH_CONFIG_LC).exports)	\
		-output /dev/null $(_vstdout)
	$(_v)$(KEXT_CREATE_SYMBOL_SET)					\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))			\
		-import $(OBJPATH)/allsymbols				\
		$(foreach symbolset,$(filter-out Unsupported,$(SYMBOL_COMPONENT_LIST)),	\
			-export $(SOURCE)/$(symbolset).exports		\
			-export $(SOURCE)/$(symbolset).$(CURRENT_ARCH_CONFIG_LC).exports)	\
		-output /dev/null $(_vstdout)

$(OBJPATH)/$(MD_SUPPORTED_KPI_FILENAME): $(EXPORTS_FILES)
	@echo SUPPORTED_KPI "($(CURRENT_ARCH_CONFIG_LC))"
	$(_v)$(SRCROOT)/config/list_supported.sh $(SOURCE) $(CURRENT_ARCH_CONFIG_LC) $@

$(OBJPATH)/$(MI_SUPPORTED_KPI_FILENAME): $(EXPORTS_FILES)
	@echo SUPPORTED_KPI "(all)"
	$(_v)$(SRCROOT)/config/list_supported.sh $(SOURCE) all $@

build_symbol_sets: check_all_exports $(SYMBOL_SET_BUILD) $(OBJPATH)/allsymbols \
			$(OBJPATH)/$(MD_SUPPORTED_KPI_FILENAME) \
			$(OBJPATH)/$(MI_SUPPORTED_KPI_FILENAME)

do_config_all::	build_symbol_sets

# There's no simple static pattern rule for these paths, so hardcode dependencies in the command list
$(SYMROOT_INSTALL_KEXT_MACHO_FILES): ALWAYS
	$(_v)$(MKDIR) $(dir $@)
	$(_v)if [ $(OBJROOT)/.symbolset.timestamp -nt $@ ]; then		\
		echo INSTALLSYM symbolset $(notdir $@) "($(CURRENT_ARCH_CONFIG_LC))";	\
		$(INSTALL) $(EXEC_INSTALL_FLAGS) $(OBJPATH)/$(@F).symbolset $@;	\
		cmdstatus=$$?;							\
	else									\
		echo INSTALLSYM symbolset $(notdir $@) "($(CURRENT_ARCH_CONFIG_LC))";	\
		$(LIPO) -create $@ $(OBJPATH)/$(@F).symbolset -output $@ 2>/dev/null || true;	\
		cmdstatus=$$?;							\
	fi;									\
	exit $$cmdstatus

.PHONY: symroot_kext_plists

symroot_kext_plists: $(SYMROOT_INSTALL_KEXT_PLISTS)

$(SYMROOT_INSTALL_KEXT_PLISTS): $(SYMROOT)/% : $(SOURCE)/%
	$(_v)$(MKDIR) $(dir $@)
	@echo INSTALLSYM kextplist $*
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@
	$(_v)$(NEWVERS) $@ $(_vstdout)

.PHONY: dstroot_kext_plists

dstroot_kext_plists: $(DSTROOT_INSTALL_KEXT_PLISTS)

$(DSTROOT_INSTALL_KEXT_PLISTS): $(INSTALL_KEXT_DIR)/% : $(SYMROOT)/%
	$(_v)$(MKDIR) $(dir $@)
	@echo INSTALL kextplist $*
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@

$(DSTROOT_INSTALL_KEXT_MACHO_FILES): $(INSTALL_KEXT_DIR)/% : $(SYMROOT)/%
	$(_v)$(MKDIR) $(dir $@)
	@echo INSTALL $(notdir $@) "($(CURRENT_ARCH_CONFIG_LC))"
	$(_v)$(INSTALL) $(EXEC_INSTALL_FLAGS) $< $@

$(DSTROOT)/$(KRESDIR)/$(MD_SUPPORTED_KPI_FILENAME) $(DSTROOT)/$(KRESDIR)/$(MI_SUPPORTED_KPI_FILENAME): $(DSTROOT)/$(KRESDIR)/% : $(OBJPATH)/%
	$(_v)$(MKDIR) $(dir $@)
	@echo INSTALL $*
	$(_v)$(INSTALL) $(INSTALL_FLAGS) $< $@

install_symbol_sets:	$(SYMROOT_INSTALL_KEXT_MACHO_FILES) \
			symroot_kext_plists \
			$(DSTROOT_INSTALL_KEXT_MACHO_FILES) \
			dstroot_kext_plists \
			$(DSTROOT)/$(KRESDIR)/$(MD_SUPPORTED_KPI_FILENAME) \
			$(DSTROOT)/$(KRESDIR)/$(MI_SUPPORTED_KPI_FILENAME)

do_build_install_primary::	install_symbol_sets

$(OBJPATH)/kernel-kpi.exp: $(EXPORTS_FILES)
	$(_v)$(SOURCE)/generate_linker_exports.sh $@ $+

.PHONY: build_mach_kernel_exports

build_mach_kernel_exports: $(OBJPATH)/kernel-kpi.exp

do_build_all:: build_mach_kernel_exports

include $(MakeInc_rule)
include $(MakeInc_dir)
