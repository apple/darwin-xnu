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

SYMBOL_SET_PLIST_COMPONENT_LIST := $(SYMBOL_COMPONENT_LIST) Kasan

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

EXPORTS_FILES = $(foreach symbolset,$(SYMBOL_COMPONENT_LIST),$(symbolset).exports $(symbolset).$(EXPORT_SOURCE_ARCH_CONFIG_LC).exports $(notdir $(wildcard $(SOURCE)/$(symbolset).$(EXPORT_SOURCE_ARCH_CONFIG_LC).$(PLATFORM).exports))) Unused.exports

Kasan_EXPORTS := $(SRCROOT)/san/Kasan.exports
ifeq ($(KASAN),1)
Kasan_EXPORTS := $(SRCROOT)/san/Kasan_kasan.exports
endif

SYMBOL_SET_BUILD = $(foreach symbolset, $(SYMBOL_COMPONENT_LIST), $(OBJPATH)/$(symbolset).symbolset)
SYMBOL_SET_PLIST_BUILD = $(foreach symbolset, $(SYMBOL_SET_PLIST_COMPONENT_LIST), $(OBJPATH)/$(symbolset).symbolset.plist)

define symbol_set_rule
$(1)_EXPORTS := $(addprefix $(SOURCE)/,$(filter $(1)%,$(EXPORTS_FILES)))
$(OBJPATH)/$(1).symbolset: MY_EXPORTS_ARGS := $$(foreach file,$$($(1)_EXPORTS),-export $$(file))
$(OBJPATH)/$(1).symbolset: $$($(1)_EXPORTS) $(OBJPATH)/allsymbols $(KEXT_CREATE_SYMBOL_SET)
	@$$(LOG_SYMBOLSET) "$(ColorF)$(1)$(Color0) ($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))"
	$(_v)$(KEXT_CREATE_SYMBOL_SET)			\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))	\
		-import $(OBJPATH)/allsymbols		\
		$$(MY_EXPORTS_ARGS)			\
		-output $$@ $(_vstdout)
endef

define symbol_set_plist_rule
$(1)_KEXT_PLIST := $$(filter %/$(1).kext/Info.plist,$$(SYMROOT_INSTALL_KEXT_PLISTS))
$(OBJPATH)/$(1).symbolset.plist: $$($(1)_KEXT_PLIST) $$($(1)_EXPORTS)
	@$$(LOG_SYMBOLSETPLIST) "$(ColorF)$(1)$(Color0) ($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))"
	$(_v)$(SOURCE)/generate_symbolset_plist.sh	$$@ $$+ $(_vstdout)
	$(_v)$(PLUTIL) -lint -s $$@
endef

$(foreach symbolset,$(SYMBOL_COMPONENT_LIST),$(eval $(call symbol_set_rule,$(symbolset))))
$(foreach symbolset,$(SYMBOL_SET_PLIST_COMPONENT_LIST),$(eval $(call symbol_set_plist_rule,$(symbolset))))

$(OBJPATH)/symbolsets.plist: $(SYMBOL_SET_PLIST_BUILD)
	$(_v)$(SOURCE)/generate_combined_symbolsets_plist.sh $@ $^ $(_vstdout)
	$(_v)$(PLUTIL) -convert binary1 -s $@

$(OBJPATH)/allsymbols: $(OBJPATH)/$(KERNEL_FILE_NAME)
	$(_v)$(NM) -gj $< | sort -u > $@

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
	@$(LOG_SUPPORTED_KPI) "$(CURRENT_ARCH_CONFIG_LC)"
	$(_v)$(SRCROOT)/config/list_supported.sh $(SOURCE) $(EXPORT_SOURCE_ARCH_CONFIG_LC) $@

$(OBJPATH)/$(MI_SUPPORTED_KPI_FILENAME): $(EXPORTS_FILES)
	@$(LOG_SUPPORTED_KPI) "all"
	$(_v)$(SRCROOT)/config/list_supported.sh $(SOURCE) all $@

build_symbol_sets: check_all_exports $(SYMBOL_SET_BUILD) $(OBJPATH)/allsymbols \
			$(OBJPATH)/$(MD_SUPPORTED_KPI_FILENAME) \
			$(OBJPATH)/$(MI_SUPPORTED_KPI_FILENAME)

do_config_all::	build_symbol_sets

# There's no simple static pattern rule for these paths, so hardcode dependencies in the command list
$(SYMROOT_INSTALL_KEXT_MACHO_FILES): ALWAYS
	$(_v)$(MKDIR) $(dir $@)
	@$(LOG_INSTALLSYM) "symbolset $(notdir $@)$(Color0) ($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))"
	$(_v)if [ $(OBJROOT)/.symbolset.timestamp -nt $@ ]; then		\
		$(INSTALL) $(EXEC_INSTALL_FLAGS) $(OBJPATH)/$(@F).symbolset $@;	\
		cmdstatus=$$?;							\
	else									\
		$(LIPO) -create $@ $(OBJPATH)/$(@F).symbolset -output $@ 2>/dev/null || true;	\
		cmdstatus=$$?;							\
	fi;									\
	exit $$cmdstatus

$(SYMROOT_INSTALL_KEXT_PLISTS): $(SYMROOT)/% : $(SOURCE)/%
	$(_v)$(MKDIR) $(dir $@)
	@$(LOG_INSTALLSYM) "kextplist$(Color0) $(ColorF)$*"
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@
	$(_v)$(NEWVERS) $@ $(_vstdout)

$(DSTROOT_INSTALL_KEXT_PLISTS): $(INSTALL_KEXT_DIR)/% : $(SYMROOT)/%
	$(_v)$(MKDIR) $(dir $@)
	@$(LOG_INSTALLSYM) "kextplist$(Color0) $(ColorF)$*"
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@

$(DSTROOT_INSTALL_KEXT_MACHO_FILES): $(INSTALL_KEXT_DIR)/% : $(SYMROOT)/% ALWAYS
	$(_v)$(MKDIR) $(dir $@)
	@$(LOG_INSTALL) "$(notdir $@)$(Color0) ($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))"
	$(_v)$(INSTALL) $(EXEC_INSTALL_FLAGS) $< $@

$(DSTROOT)/$(KRESDIR)/$(MD_SUPPORTED_KPI_FILENAME) $(DSTROOT)/$(KRESDIR)/$(MI_SUPPORTED_KPI_FILENAME): $(DSTROOT)/$(KRESDIR)/% : $(OBJPATH)/%
	$(_v)$(MKDIR) $(dir $@)
	@$(LOG_INSTALL) "$*"
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
	$(_v)$(SOURCE)/generate_linker_exports.sh $@ $+ $(Kasan_EXPORTS)

$(OBJPATH)/all-alias.exp: $(EXPORTS_FILES)
	$(_v)$(SOURCE)/generate_linker_aliases.sh $@ $+ $(Kasan_EXPORTS)

do_build_all:: $(OBJPATH)/all-kpi.exp $(OBJPATH)/all-alias.exp $(OBJPATH)/symbolsets.plist

include $(MakeInc_rule)
include $(MakeInc_dir)
