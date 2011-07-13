export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTALL_SHARE_MISC_LIST =	\
	trace.codes

include $(MakeInc_rule)
include $(MakeInc_dir)

SHARE_MISC_DIR = usr/share/misc

INSTALL_SHARE_MISC_FILES = \
	$(addprefix $(DSTROOT)/$(SHARE_MISC_DIR)/, $(INSTALL_SHARE_MISC_LIST))

$(INSTALL_SHARE_MISC_FILES): $(DSTROOT)/$(SHARE_MISC_DIR)/% : %
	@echo Installing $< in $(dir $@)
	$(_v) $(MKDIR) $(DSTROOT)/$(SHARE_MISC_DIR);	\
	$(RM) $(RMFLAGS) $@;				\
	$(INSTALL) $(INSTALL_FLAGS) $< $(dir $@);

do_build_install: $(INSTALL_SHARE_MISC_FILES)
