export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# Special handling for x86_64h which shares a MASTER config file with x86_64:
ifeq ($(CURRENT_ARCH_CONFIG_LC),x86_64h)
DOCONF_ARCH_CONFIG_LC = x86_64
else
DOCONF_ARCH_CONFIG_LC = $(CURRENT_ARCH_CONFIG_LC)
endif

MASTERCONFDIR = $(SRCROOT)/config
DOCONFDEPS = $(addprefix $(MASTERCONFDIR)/, MASTER MASTER.$(DOCONF_ARCH_CONFIG_LC)) \
	$(addprefix $(SOURCE)/, Makefile.template Makefile.$(DOCONF_ARCH_CONFIG_LC) files files.$(DOCONF_ARCH_CONFIG_LC))

ifneq (,$(wildcard $(MASTERCONFDIR)/MASTER.$(DOCONF_ARCH_CONFIG_LC).$(CURRENT_MACHINE_CONFIG_LC)))
DOCONFDEPS += $(MASTERCONFDIR)/MASTER.$(DOCONF_ARCH_CONFIG_LC).$(CURRENT_MACHINE_CONFIG_LC)
endif

$(TARGET)/$(CURRENT_KERNEL_CONFIG)/Makefile: $(SRCROOT)/SETUP/config/doconf $(OBJROOT)/SETUP/config $(DOCONFDEPS)
	$(_v)$(MKDIR) $(TARGET)/$(CURRENT_KERNEL_CONFIG)
	$(_v)$(SRCROOT)/SETUP/config/doconf -c -cpu $(DOCONF_ARCH_CONFIG_LC) -soc $(CURRENT_MACHINE_CONFIG_LC) -platform $(PLATFORM) -d $(TARGET)/$(CURRENT_KERNEL_CONFIG) -s $(SOURCE) -m $(MASTERCONFDIR) $(CURRENT_KERNEL_CONFIG)

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
		build_all

do_build_all:: do_all

include $(MakeInc_rule)
include $(MakeInc_dir)
