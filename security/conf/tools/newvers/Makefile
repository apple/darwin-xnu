export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

COMP_SUBDIRS = \

INST_SUBDIRS = \


#
# Who and where
#
BINDIR= 
ifneq ($(MACHINE_CONFIG), DEFAULT)
DSTDIR= $(strip $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)_$(MACHINE_CONFIG)/$(COMPONENT)/)
else
DSTDIR= $(strip $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/$(COMPONENT)/)
endif
PROGRAM= $(DSTDIR)newvers

# 
# How to install it
#
IFLAGS= -c -m 555

$(PROGRAM): $(DSTDIR)% : $(SOURCE)%.csh
	@-$(RM) $(RMFLAGS) $(notdir $(PROGRAM)).VERS 
	@sed -e "s/#PROGRAM.*/#`vers_string $(notdir $(PROGRAM))`/" \
		< $< >$(notdir $(PROGRAM)).VERS;
	@install $(IFLAGS) $(notdir $(PROGRAM)).VERS $(PROGRAM);
	@-$(RM) $(RMFLAGS) $(notdir $(PROGRAM)).VERS;

do_build_setup: $(PROGRAM)

do_build_all:

setup_build_install:

do_build_install:

include $(MakeInc_rule)
include $(MakeInc_dir)
