export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

OBJS = kextsymboltool.o

CFLAGS = -isysroot $(HOST_SDKROOT) -mmacosx-version-min=$(HOST_OS_VERSION) -g -O0 -I$(SOURCE) -I.

WARNFLAGS = -Wall

LDFLAGS = -isysroot $(HOST_SDKROOT) -mmacosx-version-min=$(HOST_OS_VERSION) -L$(HOST_SPARSE_SDKROOT)/usr/local/lib/system -lstdc++
ifneq ($(HOST_SPARSE_SDKROOT),/)
LDFLAGS += -lmacho
endif

.SparseSDK: ALWAYS
	$(_v)echo '$(HOST_SPARSE_SDKROOT)' | cmp -s - $@ || echo '$(HOST_SPARSE_SDKROOT)' > $@

kextsymboltool: $(OBJS) .SparseSDK
	@echo HOST_LD $@
	$(_v)$(HOST_CC) $(LDFLAGS) -o $@ $(OBJS)
	@echo HOST_CODESIGN $@
	$(_v)env CODESIGN_ALLOCATE=$(HOST_CODESIGN_ALLOCATE) $(HOST_CODESIGN) -s - $@

%.o: %.c
	@echo HOST_CC $@
	$(_v)$(HOST_CC) $(WARNFLAGS) $(CFLAGS) -c -o $@ $<

do_build_setup:: kextsymboltool

include $(MakeInc_rule)
include $(MakeInc_dir)
