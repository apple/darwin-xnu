export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

ifneq ($(MACHINE_CONFIG), DEFAULT)
export COMPOBJROOT=$(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)_$(MACHINE_CONFIG)/$(COMPONENT)
else
export COMPOBJROOT=$(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/$(COMPONENT)
endif

do_all: 
	@echo "[ $(SOURCE) ] Starting do_all  $(COMPONENT) $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)";		\
	($(MKDIR) $(COMPOBJROOT)/kmod;					\
	cd $(COMPOBJROOT)/kmod;						\
	${MAKE} MAKEFILES=$(SOURCE)/Makefile.kmod			\
		TARGET=$(TARGET)					\
		do_build_all						\
	);								\
	echo "[ $(SOURCE) ] Returning do_all $(COMPONENT) $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)";

do_build_all:	do_all

do_install: 
	@echo "[ $(SOURCE) ] Starting do_install  $(COMPONENT) $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)";		\
	($(MKDIR) $(COMPOBJROOT)/kmod;					\
	cd $(COMPOBJROOT)/kmod;						\
	${MAKE} MAKEFILES=$(SOURCE)/Makefile.kmod			\
		TARGET=$(TARGET)					\
		do_build_install					\
	);								\
	echo "[ $(SOURCE) ] Returning do_install $(COMPONENT) $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)";

do_build_install:	do_install

include $(MakeInc_rule)
include $(MakeInc_dir)
