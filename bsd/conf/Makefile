export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MASTER_CPU_PER_SOC = $(SOURCE)/MASTER.$(CURRENT_ARCH_CONFIG_LC).$(CURRENT_MACHINE_CONFIG_LC)

$(TARGET)/$(CURRENT_KERNEL_CONFIG)/Makefile :  $(SOURCE)/MASTER  \
		$(SOURCE)/MASTER.$(CURRENT_ARCH_CONFIG_LC) \
		$(SOURCE)/Makefile.template  \
		$(SOURCE)/Makefile.$(CURRENT_ARCH_CONFIG_LC)  \
		$(SOURCE)/files \
		$(SOURCE)/files.$(CURRENT_ARCH_CONFIG_LC)
	$(_v)$(MKDIR) $(addsuffix /conf, $(TARGET)); \
	cd $(addsuffix /conf, $(TARGET)); \
	rm -f $(notdir $?); \
	cp  $? .; \
	if [ $(MASTER_CPU_PER_SOC) -nt $@ ]; then cp $(MASTER_CPU_PER_SOC) .; fi; \
	$(SRCROOT)/SETUP/config/doconf -c -cpu $(CURRENT_ARCH_CONFIG_LC) -soc $(CURRENT_MACHINE_CONFIG_LC) -d  $(TARGET)/$(CURRENT_KERNEL_CONFIG) $(CURRENT_KERNEL_CONFIG);

do_all: $(TARGET)/$(CURRENT_KERNEL_CONFIG)/Makefile
	$(_v)${MAKE} \
		-C $(TARGET)/$(CURRENT_KERNEL_CONFIG)			\
		-f $(TARGET)/$(CURRENT_KERNEL_CONFIG)/Makefile		\
		CURRENT_KERNEL_CONFIG=${CURRENT_KERNEL_CONFIG}		\
		CURRENT_ARCH_CONFIG=${CURRENT_ARCH_CONFIG}		\
		CURRENT_MACHINE_CONFIG=${CURRENT_MACHINE_CONFIG}	\
		SOURCE=$(subst conf/,,$(SOURCE))			\
		TARGET=${TARGET}					\
		OBJPATH=${OBJPATH}					\
		build_all;

do_build_all:: do_all 

include $(MakeInc_rule)
include $(MakeInc_dir)
