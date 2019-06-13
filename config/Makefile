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
	System.kext/PlugIns/Kasan.kext/Info.plist \
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

# In general you want it to be possible to have a CPU sub-type's symbol exports
# alias to the parent type's exports. This is a special-case way to handle it
# for now:
ifeq ($(CURRENT_ARCH_CONFIG_LC),x86_64h)
EXPORT_SOURCE_ARCH_CONFIG_LC = x86_64
else
EXPORT_SOURCE_ARCH_CONFIG_LC = $(CURRENT_ARCH_CONFIG_LC)
endif

KEXT_MACHO_LIST = $(foreach symbolset,$(filter-out Dummy,$(SYMBOL_COMPONENT_LIST)),System.kext/PlugIns/$(symbolset).kext/$(symbolset))
KEXT_PLIST_LIST += $(foreach symbolset,$(filter-out Dummy,$(SYMBOL_COMPONENT_LIST)),System.kext/PlugIns/$(symbolset).kext/Info.plist)

SYMROOT_INSTALL_KEXT_MACHO_FILES = $(addprefix $(SYMROOT)/,$(KEXT_MACHO_LIST))
DSTROOT_INSTALL_KEXT_MACHO_FILES = $(addprefix $(INSTALL_KEXT_DIR)/,$(KEXT_MACHO_LIST))

SYMROOT_INSTALL_KEXT_PLISTS = $(addprefix $(SYMROOT)/,$(KEXT_PLIST_LIST))
DSTROOT_INSTALL_KEXT_PLISTS = $(addprefix $(INSTALL_KEXT_DIR)/,$(KEXT_PLIST_LIST))

EXPORTS_FILES = $(foreach symbolset,$(SYMBOL_COMPONENT_LIST),$(symbolset).exports $(symbolset).$(EXPORT_SOURCE_ARCH_CONFIG_LC).exports) Unused.exports

SYMBOL_SET_BUILD = $(foreach symbolset, $(SYMBOL_COMPONENT_LIST), $(OBJPATH)/$(symbolset).symbolset)

ifeq ($(KASAN),1)
KASAN_EXPORTS = $(SRCROOT)/san/Kasan_kasan.exports
endif

$(OBJPATH)/allsymbols: $(OBJPATH)/$(KERNEL_FILE_NAME)
	$(_v)$(NM) -gj $< > $@

$(SYMBOL_SET_BUILD): $(OBJPATH)/%.symbolset :  %.exports %.$(EXPORT_SOURCE_ARCH_CONFIG_LC).exports $(OBJPATH)/allsymbols $(KEXT_CREATE_SYMBOL_SET)
	@echo "$(ColorH)SYMBOLSET$(Color0)  $(ColorF)$*$(Color0) \"($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))\""
	$(_v)$(KEXT_CREATE_SYMBOL_SET)					\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))			\
		-import $(OBJPATH)/allsymbols				\
		-export $(SOURCE)/$*.exports				\
		-export $(SOURCE)/$*.$(EXPORT_SOURCE_ARCH_CONFIG_LC).exports	\
		-output $@ $(_vstdout)

.PHONY: check_all_exports

check_all_exports: $(OBJPATH)/allsymbols $(KEXT_CREATE_SYMBOL_SET)
	$(_v)$(KEXT_CREATE_SYMBOL_SET)					\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))			\
		-import $(OBJPATH)/allsymbols				\
		$(foreach symbolset,$(filter-out Private,$(SYMBOL_COMPONENT_LIST)),	\
			-export $(SOURCE)/$(symbolset).exports		\
			-export $(SOURCE)/$(symbolset).$(EXPORT_SOURCE_ARCH_CONFIG_LC).exports)	\
		-output /dev/null $(_vstdout)
	$(_v)$(KEXT_CREATE_SYMBOL_SET)					\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))			\
		-import $(OBJPATH)/allsymbols				\
		$(foreach symbolset,$(filter-out Unsupported,$(SYMBOL_COMPONENT_LIST)),	\
			-export $(SOURCE)/$(symbolset).exports		\
			-export $(SOURCE)/$(symbolset).$(EXPORT_SOURCE_ARCH_CONFIG_LC).exports)	\
		-output /dev/null $(_vstdout)

$(OBJPATH)/$(MD_SUPPORTED_KPI_FILENAME): $(EXPORTS_FILES)
	@echo "$(ColorH)SUPPORTED_KPI$(Color0) \"($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))\""
	$(_v)$(SRCROOT)/config/list_supported.sh $(SOURCE) $(EXPORT_SOURCE_ARCH_CONFIG_LC) $@

$(OBJPATH)/$(MI_SUPPORTED_KPI_FILENAME): $(EXPORTS_FILES)
	@echo "$(ColorH)SUPPORTED_KPI$(Color0) \"($(ColorLF)all$(Color0))\""
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

$(SYMROOT_INSTALL_KEXT_PLISTS): $(SYMROOT)/% : $(SOURCE)/%
	$(_v)$(MKDIR) $(dir $@)
	@echo "$(ColorH)INSTALLSYM$(ColorH) $(ColorLF)kextplist$(Color0) $(ColorF)$*$(Color0)"
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@
	$(_v)$(NEWVERS) $@ $(_vstdout)

$(DSTROOT_INSTALL_KEXT_PLISTS): $(INSTALL_KEXT_DIR)/% : $(SYMROOT)/%
	$(_v)$(MKDIR) $(dir $@)
	@echo "$(ColorH)INSTALL$(ColorH)    $(ColorLF)kextplist$(Color0) $(ColorF)$*$(Color0)"
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@

$(DSTROOT_INSTALL_KEXT_MACHO_FILES): $(INSTALL_KEXT_DIR)/% : $(SYMROOT)/% ALWAYS
	$(_v)$(MKDIR) $(dir $@)
	@echo "$(ColorF)INSTALL$(Color0)    $(ColorF)$(notdir $@)$(Color0) \"($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))\""
	$(_v)$(INSTALL) $(EXEC_INSTALL_FLAGS) $< $@

$(DSTROOT)/$(KRESDIR)/$(MD_SUPPORTED_KPI_FILENAME) $(DSTROOT)/$(KRESDIR)/$(MI_SUPPORTED_KPI_FILENAME): $(DSTROOT)/$(KRESDIR)/% : $(OBJPATH)/%
	$(_v)$(MKDIR) $(dir $@)
	@echo "$(ColorH)INSTALL$(Color0)    $(ColorF)$*$(Color0)"
	$(_v)$(INSTALL) $(INSTALL_FLAGS) $< $@

ifneq ($(INSTALL_KASAN_ONLY),1)
do_config_install::	$(SYMROOT_INSTALL_KEXT_MACHO_FILES) \
				$(SYMROOT_INSTALL_KEXT_PLISTS) \
				$(DSTROOT_INSTALL_KEXT_MACHO_FILES) \
				$(DSTROOT_INSTALL_KEXT_PLISTS) \
				$(DSTROOT)/$(KRESDIR)/$(MD_SUPPORTED_KPI_FILENAME) \
				$(DSTROOT)/$(KRESDIR)/$(MI_SUPPORTED_KPI_FILENAME)
endif


$(OBJPATH)/all-kpi.exp: $(EXPORTS_FILES)
	$(_v)$(SOURCE)/generate_linker_exports.sh $@ $+ $(KASAN_EXPORTS)

$(OBJPATH)/all-alias.exp: $(EXPORTS_FILES)
	$(_v)$(SOURCE)/generate_linker_aliases.sh $@ $+ $(KASAN_EXPORTS)

do_build_all:: $(OBJPATH)/all-kpi.exp $(OBJPATH)/all-alias.exp

include $(MakeInc_rule)
include $(MakeInc_dir)
