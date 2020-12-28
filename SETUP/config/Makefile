export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

OBJS = externs.o main.o mkheaders.o mkioconf.o mkmakefile.o	\
	openp.o searchp.o lexer.yy.o parser.o

CFLAGS = -isysroot $(HOST_SDKROOT) -mmacosx-version-min=$(HOST_OS_VERSION) -g -O0 -I$(SOURCE) -I.
CFLAGS += -DYY_NO_INPUT

WARNFLAGS = -Wall

LDFLAGS = -isysroot $(HOST_SDKROOT) -mmacosx-version-min=$(HOST_OS_VERSION)

config: $(OBJS)
	$(call makelog,$(ColorH)HOST_LD$(Color0)       $(ColorF)$@$(Color0))
	$(_v)$(HOST_CC) $(LDFLAGS) -o $@ $^
	$(call makelog,$(ColorH)HOST_CODESIGN$(Color0) $(ColorF)$@$(Color0))
	$(_v)env CODESIGN_ALLOCATE=$(HOST_CODESIGN_ALLOCATE) $(HOST_CODESIGN) -s - $@

%.o: %.c
	$(call makelog,$(ColorH)HOST_CC$(Color0)       $(ColorF)$@$(Color0))
	$(_v)$(HOST_CC) $(WARNFLAGS) $(CFLAGS) -c -o $@ $<

parser.c: parser.y
	$(call makelog,$(ColorH)HOST_BISON$(Color0)    $(ColorF)$@$(Color0))
	$(_v)$(HOST_BISON) -y -d -d -o $@ $<

lexer.yy.c: lexer.l
	$(call makelog,$(ColorH)HOST_FLEX$(Color0)     $(ColorF)$@$(Color0))
	$(_v)env M4=$(HOST_GM4) $(HOST_FLEX) --header-file=lexer.yy.h -o $@ $<

main.o mkheaders.o mkioconf.o mkmakefile.o lexer.yy.c: parser.c

do_build_setup:: config

include $(MakeInc_rule)
include $(MakeInc_dir)
