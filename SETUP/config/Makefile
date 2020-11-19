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
	@$(LOG_HOST_LD) "$@"
	$(_v)$(HOST_CC) $(LDFLAGS) -o $@ $^
	@$(LOG_HOST_CODESIGN) "$@"
	$(_v)env CODESIGN_ALLOCATE=$(HOST_CODESIGN_ALLOCATE) $(HOST_CODESIGN) -s - $@

%.o: %.c
	@$(LOG_HOST_CC) "$@"
	$(_v)$(HOST_CC) $(WARNFLAGS) $(CFLAGS) -c -o $@ $<

parser.c: parser.y
	@$(LOG_HOST_BISON) "$@"
	$(_v)$(HOST_BISON) -y -d -d -o $@ $<

lexer.yy.c: lexer.l
	@$(LOG_HOST_FLEX) "$@"
	$(_v)env M4=$(HOST_GM4) $(HOST_FLEX) --header-file=lexer.yy.h -o $@ $<

main.o mkheaders.o mkioconf.o mkmakefile.o lexer.yy.c: parser.c

do_build_setup:: config

include $(MakeInc_rule)
include $(MakeInc_dir)
