export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

COMPOBJROOT = $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/$(COMPONENT)

do_all: 
	@echo "[ $(SOURCE) ] Starting do_all  $(COMPONENT) $(MACH_KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)";		\
	($(MKDIR) $(COMPOBJROOT)/kmod;					\
	cd $(COMPOBJROOT)/kmod;						\
	${MAKE} MAKEFILES=$(SOURCE)/Makefile.kmod			\
		TARGET=$(TARGET)					\
		do_build_all						\
	);								\
	echo "[ $(SOURCE) ] Returning do_all $(COMPONENT) $(MACH_KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)";

do_build_all:	do_all

do_install: 
	@echo "[ $(SOURCE) ] Starting do_install  $(COMPONENT) $(MACH_KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)";		\
	($(MKDIR) $(COMPOBJROOT)/kmod;					\
	cd $(COMPOBJROOT)/kmod;						\
	${MAKE} MAKEFILES=$(SOURCE)/Makefile.kmod			\
		TARGET=$(TARGET)					\
		do_build_install					\
	);								\
	echo "[ $(SOURCE) ] Returning do_install $(COMPONENT) $(MACH_KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)";

do_build_install:	do_install

include $(MakeInc_rule)
include $(MakeInc_dir)
