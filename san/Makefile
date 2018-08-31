export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \

PRIVATE_DATAFILES = \

KERNELFILES = \

PRIVATE_KERNELFILES = \
	memintrinsics.h

# Available only in xnu proper
PRIVATE_XNUFILES = \
	kasan.h

INSTALL_MI_LIST = ${DATAFILES}
INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}
INSTALL_KF_MI_LIST = ${KERNELFILES}
INSTALL_KF_MI_LCL_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_LIST = ${PRIVATE_XNUFILES} ${KERNELFILES} ${PRIVATE_KERNELFILES}

INSTALL_MI_DIR = san
EXPORT_MI_DIR = san
COMP_SUBDIRS = conf

.DELETE_ON_ERROR:
$(OBJROOT)/san/kasan-blacklist-%: $(SOURCE)/kasan-blacklist $(SOURCE)/kasan-blacklist-%
	@echo "$(ColorH)GENERATING$(Color0)    $(ColorLF)$(notdir $@)$(Color0)"
	$(_v)sed -e 's,^src:\./,src:'"$(SRCROOT)/," $^ > $@
	$(_v)$(SOURCE)/tools/validate_blacklist.sh "$@"

do_build_setup:: $(OBJROOT)/san/kasan-blacklist-x86_64 $(OBJROOT)/san/kasan-blacklist-arm64

#
# Kasan System.kext plugin
#

DSTROOT_KEXT_PATH = $(addprefix $(DSTROOT)$(INSTALL_EXTENSIONS_DIR),/System.kext/PlugIns/Kasan.kext)
SYMROOT_KEXT_PATH = $(addprefix $(SYMROOT),/System.kext/PlugIns/Kasan.kext)

ifneq ($(INSTALL_KASAN_ONLY),1)
DSTROOT_KEXT = $(DSTROOT_KEXT_PATH)/Kasan
SYMROOT_KEXT = $(SYMROOT_KEXT_PATH)/Kasan
endif

ifeq ($(KASAN),1)
DSTROOT_KEXT += $(DSTROOT_KEXT_PATH)/Kasan_kasan
SYMROOT_KEXT += $(SYMROOT_KEXT_PATH)/Kasan_kasan
endif

# Our external dependency on allsymbols is fine because this runs in a later phase (config_install vs. config_all)
$(OBJPATH)/%.symbolset: $(SOURCE)/%.exports
	@echo "$(ColorH)SYMBOLSET$(Color0)  $(ColorF)$*$(Color0) \"($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))\""
	$(_v)$(KEXT_CREATE_SYMBOL_SET)			\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))	\
		-import $(OBJPATH)/allsymbols		\
		-export $<		                \
		-output $@ $(_vstdout)

$(DSTROOT_KEXT): $(DSTROOT_KEXT_PATH)/% : $(OBJPATH)/%.symbolset
	$(_v)$(MKDIR) $(dir $@)
	@echo "$(ColorF)INSTALL$(Color0)    $(ColorF)$(notdir $@)$(Color0) \"($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))\""
	$(_v)$(INSTALL) $(EXEC_INSTALL_FLAGS) $< $@

$(SYMROOT_KEXT): $(SYMROOT_KEXT_PATH)/% : $(DSTROOT_KEXT_PATH)/%
	$(_v)$(MKDIR) $(dir $@)
	@echo "$(ColorF)INSTALL$(Color0)    $(ColorF)$(notdir $@)$(Color0) \"($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))\""
	$(_v)$(INSTALL) $(EXEC_INSTALL_FLAGS) $< $@

do_config_install:: $(DSTROOT_KEXT) $(SYMROOT_KEXT)


# Install helper scripts

ifeq ($(KASAN),1)
KASAN_HELPER_SCRIPTS += $(DSTROOT)/$(DEVELOPER_EXTRAS_DIR)/kasan_install
endif

$(KASAN_HELPER_SCRIPTS): $(DSTROOT)/$(DEVELOPER_EXTRAS_DIR)/% : $(SOURCE)/tools/%
	$(_v)$(MKDIR) $(dir $@)
	@echo "$(ColorH)INSTALL$(Color0)    $(ColorF)$(@F)$(Color0)"
	$(_v)$(INSTALL) $(EXEC_INSTALL_FLAGS) $< $@

do_config_install:: $(KASAN_HELPER_SCRIPTS)

include $(MakeInc_rule)
include $(MakeInc_dir)
