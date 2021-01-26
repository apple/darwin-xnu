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
	ksancov.h \
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
$(OBJROOT)/san/kasan-blacklist-%: $(SOURCE)/kasan-blacklist $(SOURCE)/ubsan-blacklist $(SOURCE)/kasan-blacklist-%
	@$(LOG_GENERATE) "$(notdir $@)"
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
SYMBOL_SET_BUILD = $(OBJPATH)/Kasan.symbolset
endif

ifeq ($(KASAN),1)
DSTROOT_KEXT += $(DSTROOT_KEXT_PATH)/Kasan_kasan
SYMROOT_KEXT += $(SYMROOT_KEXT_PATH)/Kasan_kasan
SYMBOL_SET_BUILD += $(OBJPATH)/Kasan_kasan.symbolset
endif

ifneq ($(RC_ProjectName),xnu_libraries)
# Our external dependency on allsymbols is fine because this runs in a later phase (config_install vs. config_all)
$(OBJPATH)/%.symbolset: $(SOURCE)/%.exports
	@$(LOG_SYMBOLSET) "$*$(Color0) ($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))"
	$(_v)$(KEXT_CREATE_SYMBOL_SET)			\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))	\
		-import $(OBJPATH)/allsymbols		\
		-export $<		                \
		-output $@ $(_vstdout)

$(DSTROOT_KEXT): $(DSTROOT_KEXT_PATH)/% : $(SYMROOT_KEXT_PATH)/% ALWAYS
	$(_v)$(MKDIR) $(dir $@)
	@$(LOG_INSTALL) "$(@F)$(Color0) ($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))"
	$(_v)$(INSTALL) $(EXEC_INSTALL_FLAGS) $< $@

$(SYMROOT_KEXT): $(SYMBOL_SET_BUILD) ALWAYS
	$(_v)$(MKDIR) $(dir $@)
	@$(LOG_INSTALL) "$(@F)$(Color0) ($(ColorLF)$(CURRENT_ARCH_CONFIG_LC)$(Color0))"
	$(_v)if [ $(OBJROOT)/.symbolset.timestamp -nt $@ ]; then				\
		$(INSTALL) $(EXEC_INSTALL_FLAGS) $(OBJPATH)/$(@F).symbolset $@;			\
		cmdstatus=$$?;									\
	else											\
		$(LIPO) -create $@ $(OBJPATH)/$(@F).symbolset -output $@ 2>/dev/null || true;	\
		cmdstatus=$$?;									\
	fi;											\
	exit $$cmdstatus

do_config_install:: $(SYMROOT_KEXT) $(DSTROOT_KEXT)
else
# We are building XNU as a static library - no need for the symbol kexts
endif

# Install helper scripts

ifeq ($(KASAN),1)
KASAN_HELPER_SCRIPTS += $(DSTROOT)/$(DEVELOPER_EXTRAS_DIR)/kasan_install
endif

$(KASAN_HELPER_SCRIPTS): $(DSTROOT)/$(DEVELOPER_EXTRAS_DIR)/% : $(SOURCE)/tools/%
	$(_v)$(MKDIR) $(dir $@)
	@$(LOG_INSTALL) "$(@F)"
	$(_v)$(INSTALL) $(EXEC_INSTALL_FLAGS) $< $@

do_config_install:: $(KASAN_HELPER_SCRIPTS)

include $(MakeInc_rule)
include $(MakeInc_dir)
