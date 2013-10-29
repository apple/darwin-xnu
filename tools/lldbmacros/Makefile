export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

.PHONY: lldbmacros_install

do_config_all:: lldbmacros_install

LLDBMACROS_SOURCE:=$(SRCROOT)/tools/lldbmacros/
LLDBMACROS_DEST:=$(OBJPATH)/$(DSYMKERNELSYSDIR)/$(DSYMLLDBMACROSDIR)/lldbmacros/

LLDBMACROS_PYTHON_FILES = \
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
	xnu.py \
	xnudefines.py \
	mbufdefines.py \
	netdefines.py \
	routedefines.py \
	ipc.py \
	scheduler.py \
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
	apic.py

INSTALL_LLDBMACROS_PYTHON_FILES=$(addprefix $(LLDBMACROS_DEST), $(LLDBMACROS_PYTHON_FILES))

$(INSTALL_LLDBMACROS_PYTHON_FILES): $(LLDBMACROS_DEST)% : $(LLDBMACROS_SOURCE)% 
	$(_v)$(MKDIR) $(dir $@)
	$(_v)$(PYTHON) $(LLDBMACROS_SOURCE)/core/syntax_checker.py $< $(_vstdout)
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@
	$(_v)$(TOUCH) $(LLDBMACROS_DEST)

$(LLDBMACROS_DEST)/../mach_kernel.py: $(LLDBMACROS_SOURCE)/core/xnu_lldb_init.py
	$(_v)$(MKDIR) $(dir $@)
	$(_v)$(PYTHON) $(LLDBMACROS_SOURCE)/core/syntax_checker.py $< $(_vstdout)
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@

lldbmacros_install: $(INSTALL_LLDBMACROS_PYTHON_FILES) $(LLDBMACROS_DEST)/../mach_kernel.py

include $(MakeInc_rule)
include $(MakeInc_dir)
