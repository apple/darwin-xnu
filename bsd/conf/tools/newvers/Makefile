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
DSTDIR= $(strip $(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/$(COMPONENT)/)
PROGRAM= $(DSTDIR)newvers

# 
# How to install it
#
IFLAGS= -c -m 555

$(PROGRAM): $(DSTDIR)% : $(SOURCE)%.csh
	@echo "[ $(SOURCE) ] make setup_build_all $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)";
	-$(RM) $(RMFLAGS) $(notdir $(PROGRAM)).VERS 
	sed -e "s/#PROGRAM.*/#`vers_string $(notdir $(PROGRAM))`/" \
		< $< >$(notdir $(PROGRAM)).VERS;
	install $(IFLAGS) $(notdir $(PROGRAM)).VERS $(PROGRAM);
	-$(RM) $(RMFLAGS) $(notdir $(PROGRAM)).VERS;

do_build_setup: $(PROGRAM)

do_build_all:
	@echo "[ $(SOURCE) ] make do_build_all $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)"

setup_build_install:
	@echo "[ $(SOURCE) ] make setup_build_all $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)"

do_build_install:
	@echo "[ $(SOURCE) ] make do_build_all $(KERNEL_CONFIG) $(ARCH_CONFIG) $(TARGET)"

include $(MakeInc_rule)
include $(MakeInc_dir)


