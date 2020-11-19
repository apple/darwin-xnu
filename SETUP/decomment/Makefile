export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

OBJS = decomment.o

CFLAGS = -isysroot $(HOST_SDKROOT) -mmacosx-version-min=$(HOST_OS_VERSION) -g -O0 -I$(SOURCE) -I.

WARNFLAGS = -Wall

LDFLAGS = -isysroot $(HOST_SDKROOT) -mmacosx-version-min=$(HOST_OS_VERSION)

decomment: $(OBJS)
	@$(LOG_HOST_LD) "$@"
	$(_v)$(HOST_CC) $(LDFLAGS) -o $@ $^
	@$(LOG_HOST_CODESIGN) "$@"
	$(_v)env CODESIGN_ALLOCATE=$(HOST_CODESIGN_ALLOCATE) $(HOST_CODESIGN) -s - $@

%.o: %.c
	@$(LOG_HOST_CC) "$@"
	$(_v)$(HOST_CC) $(WARNFLAGS) $(CFLAGS) -c -o $@ $<

do_build_setup:: decomment

include $(MakeInc_rule)
include $(MakeInc_dir)
