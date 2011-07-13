export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

OBJS = setsegname.o

CFLAGS = -isysroot $(HOST_SDKROOT) -g -O0 -I$(SOURCE) -I.

WARNFLAGS = -Wall

LDFLAGS = -isysroot $(HOST_SDKROOT)

setsegname: $(OBJS)
	$(_v)$(HOST_CC) $(LDFLAGS) -o $@ $^
	@echo HOST_LD $@
	$(_v)$(HOST_CODESIGN) -s - $@
	@echo HOST_CODESIGN $@

.c.o:
	$(_v)$(HOST_CC) $(WARNFLAGS) $(CFLAGS) -c -o $@ $<
	@echo HOST_CC $@

do_build_setup: setsegname

include $(MakeInc_rule)
include $(MakeInc_dir)
