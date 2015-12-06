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
	xnu.py \
	xnudefines.py \
	mbufdefines.py \
	netdefines.py \
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
	ioreg.py \
	utils.py \
	kdp.py \
	process.py \
	userspace.py \
	pci.py \
	misc.py \
	apic.py \
	kauth.py \
	usertaskgdbserver.py \
	waitq.py

ifneq ($(PLATFORM),MacOSX)
	LLDBMACROS_PYTHON_FILES+= \
		plugins/iosspeedtracer.py \
		plugins/iosspeedtracer.sh
endif

INSTALL_LLDBMACROS_PYTHON_FILES=$(addprefix $(LLDBMACROS_DEST), $(LLDBMACROS_PYTHON_FILES))

$(INSTALL_LLDBMACROS_PYTHON_FILES): $(LLDBMACROS_DEST)% : $(LLDBMACROS_SOURCE)% 
	$(_v)$(MKDIR) $(dir $@)
	$(_v)$(PYTHON) $(LLDBMACROS_SOURCE)/core/syntax_checker.py $< $(_vstdout)
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@
	$(_v)$(TOUCH) $(LLDBMACROS_DEST)

$(LLDBMACROS_BOOTSTRAP_DEST)/$(KERNEL_LLDBBOOTSTRAP_NAME): $(LLDBMACROS_SOURCE)/core/xnu_lldb_init.py
	$(_v)$(MKDIR) $(dir $@)
	$(_v)$(PYTHON) $(LLDBMACROS_SOURCE)/core/syntax_checker.py $< $(_vstdout)
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@

lldbmacros_install: $(INSTALL_LLDBMACROS_PYTHON_FILES) $(LLDBMACROS_BOOTSTRAP_DEST)/$(KERNEL_LLDBBOOTSTRAP_NAME)

include $(MakeInc_rule)
include $(MakeInc_dir)
