export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTALL_SHARE_MISC_LIST =	\
	trace.codes

INSTALL_SHARE_MISC_FILES = \
	$(addprefix $(DSTROOT)/$(INSTALL_SHARE_MISC_DIR)/, $(INSTALL_SHARE_MISC_LIST))

$(INSTALL_SHARE_MISC_FILES): $(DSTROOT)/$(INSTALL_SHARE_MISC_DIR)/% : %
	$(_v)$(MKDIR) $(DSTROOT)/$(INSTALL_SHARE_MISC_DIR)
	@echo INSTALL $(@F)
	$(_v)$(INSTALL) $(INSTALL_FLAGS) $< $@

do_build_install_primary:: $(INSTALL_SHARE_MISC_FILES)

include $(MakeInc_rule)
include $(MakeInc_dir)
