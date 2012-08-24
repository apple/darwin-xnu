export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

SETUP_SUBDIRS =

COMP_SUBDIRS = 

INST_SUBDIRS = 

ifndef OSFMK_KERNEL_CONFIG
export OSFMK_KERNEL_CONFIG = $(KERNEL_CONFIG)
endif

ifneq ($(MACHINE_CONFIG), DEFAULT)
export COMPOBJROOT=$(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)_$(MACHINE_CONFIG)/$(COMPONENT)
else
export COMPOBJROOT=$(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/$(COMPONENT)
endif

MASTER_CPU_PER_SOC = $(SOURCE)/MASTER.$(ARCH_CONFIG_LC).$(MACHINE_CONFIG_LC)

$(COMPOBJROOT)/$(OSFMK_KERNEL_CONFIG)/Makefile:  $(SOURCE)/MASTER  \
	$(SOURCE)/MASTER.$(ARCH_CONFIG_LC) \
	$(SOURCE)/Makefile.template  \
	$(SOURCE)/Makefile.$(ARCH_CONFIG_LC)  \
	$(SOURCE)/files \
	$(SOURCE)/files.$(ARCH_CONFIG_LC)
	$(_v)(doconf_target=$(addsuffix /conf, $(TARGET)); \
	$(MKDIR) $${doconf_target}; \
	cd $${doconf_target}; \
	rm -f $(notdir $?); \
	cp  $? $${doconf_target}; \
	if [ -f $(MASTER_CPU_PER_SOC) ]; then cp $(MASTER_CPU_PER_SOC) $${doconf_target}; fi; \
	$(SRCROOT)/SETUP/config/doconf -c -cpu $(ARCH_CONFIG_LC) -soc $(MACHINE_CONFIG_LC) -d  $(TARGET)/$(OSFMK_KERNEL_CONFIG) $(OSFMK_KERNEL_CONFIG); \
	);

$(COMPOBJROOT)/$(OSFMK_KERNEL_CONFIG)/platforms.h: $(COMPOBJROOT)/$(OSFMK_KERNEL_CONFIG)/Makefile
	$(_v)(cd $(COMPOBJROOT)/$(OSFMK_KERNEL_CONFIG);			\
	${RM} $@;						\
	${LN} cputypes.h $@;					\
	)

do_all: $(COMPOBJROOT)/$(OSFMK_KERNEL_CONFIG)/Makefile \
		$(COMPOBJROOT)/$(OSFMK_KERNEL_CONFIG)/platforms.h 
	$(_v)next_source=$(subst conf/,,$(SOURCE));			\
	next_relsource=$(subst conf/,,$(RELATIVE_SOURCE_PATH));		\
	${MAKE} -C $(COMPOBJROOT)/$(OSFMK_KERNEL_CONFIG)	\
		MAKEFILES=$(TARGET)/$(OSFMK_KERNEL_CONFIG)/Makefile	\
		SOURCE=$${next_source}			\
		RELATIVE_SOURCE_PATH=$${next_relsource}			\
		TARGET=$(TARGET)					\
		INCL_MAKEDEP=FALSE	\
		KERNEL_CONFIG=$(OSFMK_KERNEL_CONFIG)	\
		build_all;

do_build_all: do_all 

include $(MakeInc_rule)
include $(MakeInc_dir)
