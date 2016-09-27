export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

OBJS = installfile.o

CFLAGS = -isysroot $(HOST_SDKROOT) -mmacosx-version-min=$(HOST_OS_VERSION) -g -O0 -I$(SOURCE) -I.

WARNFLAGS = -Wall

LDFLAGS = -isysroot $(HOST_SDKROOT) -mmacosx-version-min=$(HOST_OS_VERSION)

installfile: $(OBJS)
	@echo "$(ColorH)HOST_LD$(Color0)       $(ColorF)$@$(Color0)"
	$(_v)$(HOST_CC) $(LDFLAGS) -o $@ $^
	@echo "$(ColorH)HOST_CODESIGN$(Color0) $(ColorF)$@$(Color0)"
	$(_v)env CODESIGN_ALLOCATE=$(HOST_CODESIGN_ALLOCATE) $(HOST_CODESIGN) -s - $@

%.o: %.c
	@echo "$(ColorH)HOST_CC$(Color0)       $(ColorF)$@$(Color0)"
	$(_v)$(HOST_CC) $(WARNFLAGS) $(CFLAGS) -c -o $@ $<

do_build_setup:: installfile

include $(MakeInc_rule)
include $(MakeInc_dir)
