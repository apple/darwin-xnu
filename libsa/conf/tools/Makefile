export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

SETUP_SUBDIRS = \
	doconf \
	newvers

COMP_SUBDIRS = \
	doconf \
	newvers

INST_SUBDIRS = \


setup_build_all:
	@echo "[ $(SOURCE) ] make setup_build_all $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)"

do_build_all:
	@echo "[ $(SOURCE) ] make do_build_all $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)"

setup_build_install:
	@echo "[ $(SOURCE) ] make setup_build_all $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)"

do_build_install:
	@echo "[ $(SOURCE) ] make do_build_all $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)"

include $(MakeInc_rule)
include $(MakeInc_dir)


