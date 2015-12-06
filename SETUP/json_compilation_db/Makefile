export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

OBJS = json_compilation_db.o

CFLAGS = -isysroot $(HOST_SDKROOT) -mmacosx-version-min=$(HOST_OS_VERSION) -g -O0 -I$(SOURCE) -I.

WARNFLAGS = -Wall

LDFLAGS = -isysroot $(HOST_SDKROOT) -mmacosx-version-min=$(HOST_OS_VERSION)

json_compilation_db: $(OBJS)
	@echo HOST_LD $@
	$(_v)$(HOST_CC) $(LDFLAGS) -o $@ $^
	@echo HOST_CODESIGN $@
	$(_v)env CODESIGN_ALLOCATE=$(HOST_CODESIGN_ALLOCATE) $(HOST_CODESIGN) -s - $@

%.o: %.c
	@echo HOST_CC $@
	$(_v)$(HOST_CC) $(WARNFLAGS) $(CFLAGS) -c -o $@ $<

do_build_setup:: json_compilation_db

include $(MakeInc_rule)
include $(MakeInc_dir)
