export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTALL_DTRACE_SCRIPTS_LIST =	\
	darwin.d \
	errno.d \
	io.d \
	ip.d \
	regs_x86_64.d \
	sched.d \
	signal.d \
	socket.d \
	tcp.d \
	unistd.d

ifneq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS),$(PLATFORM)),)
INSTALL_DTRACE_SCRIPTS_LIST += mptcp.d
endif

INSTALL_DTRACE_SCRIPTS_FILES = \
	$(addprefix $(DSTROOT)/$(INSTALL_DTRACE_SCRIPTS_DIR)/, $(INSTALL_DTRACE_SCRIPTS_LIST))

$(INSTALL_DTRACE_SCRIPTS_FILES): $(DSTROOT)/$(INSTALL_DTRACE_SCRIPTS_DIR)/% : %
	$(_v)$(MKDIR) $(DSTROOT)/$(INSTALL_DTRACE_SCRIPTS_DIR)
	@echo INSTALL $(@F)
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@

do_textfiles_install:: $(INSTALL_DTRACE_SCRIPTS_FILES)

include $(MakeInc_rule)
include $(MakeInc_dir)


