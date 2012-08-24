export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

OBJS = kextsymboltool.o

CFLAGS = -isysroot $(HOST_SDKROOT) -g -O0 -I$(SOURCE) -I.

WARNFLAGS = -Wall

LDFLAGS = -isysroot $(HOST_SDKROOT) -L$(HOST_SPARSE_SDKROOT)/usr/local/lib/system -lstdc++
ifneq ($(HOST_SPARSE_SDKROOT),/)
LDFLAGS += -lmacho
endif

kextsymboltool: $(OBJS)
	$(_v)$(HOST_CC) $(LDFLAGS) -o $@ $^
	@echo HOST_LD $@
	$(_v)$(HOST_CODESIGN) -s - $@
	@echo HOST_CODESIGN $@

.c.o:
	$(_v)$(HOST_CC) $(WARNFLAGS) $(CFLAGS) -c -o $@ $<
	@echo HOST_CC $@

do_build_setup: kextsymboltool

include $(MakeInc_rule)
include $(MakeInc_dir)
