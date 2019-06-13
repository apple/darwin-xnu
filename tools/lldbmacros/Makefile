export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

.PHONY: lldbmacros_install

do_config_all:: lldbmacros_install

LLDBMACROS_SOURCE:=$(SRCROOT)/tools/lldbmacros/
LLDBMACROS_BOOTSTRAP_DEST:=$(OBJPATH)/$(KERNEL_FILE_NAME).dSYM/$(DSYMLLDBMACROSDIR)
LLDBMACROS_DEST:=$(LLDBMACROS_BOOTSTRAP_DEST)/lldbmacros/
LLDBMACROS_USERDEBUG_FILES=
ifeq ($(BUILD_STATIC_LINK),1)
KERNEL_STATIC_DSYM_LLDBMACROS := $(OBJPATH)/$(KERNEL_FILE_NAME).link/$(KERNEL_FILE_NAME).dSYM/$(DSYMLLDBMACROSDIR)/lldbmacros
endif

LLDBMACROS_USERDEBUG_FILES:= \
	usertaskdebugging/__init__.py \
	usertaskdebugging/gdbserver.py \
	usertaskdebugging/interface.py \
	usertaskdebugging/rsprotocol.py \
	usertaskdebugging/target.py \
	usertaskdebugging/userprocess.py

LLDBMACROS_PYTHON_FILES = $(LLDBMACROS_USERDEBUG_FILES) \
	core/standard.py \
	core/cvalue.py \
	core/__init__.py \
	core/configuration.py \
	core/caching.py \
	core/lazytarget.py \
	core/kernelcore.py \
	core/operating_system.py \
	core/xnu_lldb_init.py \
	plugins/__init__.py \
	plugins/zprint_perf_log.py \
	atm.py \
	bank.py \
	turnstile.py \
	kevent.py \
	workqueue.py \
	xnu.py \
	xnudefines.py \
	ktrace.py \
	macho.py \
	mbufdefines.py \
	netdefines.py \
	ntstat.py \
	routedefines.py \
	ipc.py \
	ipcimportancedetail.py \
	kcdata.py \
	scheduler.py \
	structanalyze.py \
	pmap.py \
	memory.py \
	mbufs.py \
	net.py \
	skywalk.py \
	ioreg.py \
	utils.py \
	kdp.py \
	process.py \
	userspace.py \
	pci.py \
	misc.py \
	apic.py \
	kasan.py \
	kauth.py \
	usertaskgdbserver.py \
	waitq.py \
	pgtrace.py \
	xnutriage.py \
	zonetriage.py

ifneq ($(PLATFORM),MacOSX)
	LLDBMACROS_PYTHON_FILES+= \
		plugins/iosspeedtracer.py \
		plugins/iosspeedtracer.sh
endif

include $(MakeInc_rule)
include $(MakeInc_dir)

INSTALL_LLDBMACROS_PYTHON_FILES=$(addprefix $(LLDBMACROS_DEST), $(LLDBMACROS_PYTHON_FILES))
$(eval $(call INSTALLPYTHON_RULE_template,$(INSTALL_LLDBMACROS_PYTHON_FILES),$(LLDBMACROS_SOURCE)%,pydir,$(DATA_UNIFDEF),$(LLDBMACROS_DEST)))
$(eval $(call INSTALLPYTHON_RULE_template,$(LLDBMACROS_BOOTSTRAP_DEST)/$(KERNEL_LLDBBOOTSTRAP_NAME),$(LLDBMACROS_SOURCE)/core/xnu_lldb_init.py,kbpydir,$(DATA_UNIFDEF),$(LLDBMACROS_BOOTSTRAP_DEST)/))

ifeq ($(BUILD_STATIC_LINK),1)
INSTALL_STATIC_DSYM_LLDBMACROS_PYTHON_FILES=$(addprefix $(KERNEL_STATIC_DSYM_LLDBMACROS), $(LLDBMACROS_PYTHON_FILES))
$(eval $(call INSTALLPYTHON_RULE_template,$(INSTALL_STATIC_DSYM_LLDBMACROS_PYTHON_FILES),$(LLDBMACROS_SOURCE)%,sdpydir,$(DATA_UNIFDEF),$(KERNEL_STATIC_DSYM_LLDBMACROS)))
$(eval $(call INSTALLPYTHON_RULE_template,$(KERNEL_STATIC_DSYM_LLDBMACROS)/../$(KERNEL_LLDBBOOTSTRAP_NAME),$(LLDBMACROS_SOURCE)/core/xnu_lldb_init.py,kbsdpydir,$(DATA_UNIFDEF),$(KERNEL_STATIC_DSYM_LLDBMACROS)/../))
endif

lldbmacros_install: $(INSTALL_LLDBMACROS_PYTHON_FILES) $(LLDBMACROS_BOOTSTRAP_DEST)/$(KERNEL_LLDBBOOTSTRAP_NAME)
	$(_v)$(MKDIR) $(LLDBMACROS_DEST)/builtinkexts
ifeq ($(BUILD_STATIC_LINK),1)
	$(_v)$(MKDIR) $(KERNEL_STATIC_DSYM_LLDBMACROS)/builtinkexts
endif
