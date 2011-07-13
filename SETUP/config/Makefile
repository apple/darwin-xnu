export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

OBJS = externs.o main.o mkglue.o mkheaders.o mkioconf.o mkmakefile.o	\
	mkswapconf.o openp.o searchp.o lexer.yy.o parser.o

CFLAGS = -isysroot $(HOST_SDKROOT) -g -O0 -I$(SOURCE) -I.

WARNFLAGS = -Wall

LDFLAGS = -isysroot $(HOST_SDKROOT)

config: $(OBJS)
	$(_v)$(HOST_CC) $(LDFLAGS) -o $@ $^
	@echo HOST_LD $@
	$(_v)$(HOST_CODESIGN) -s - $@
	@echo HOST_CODESIGN $@

.c.o:
	$(_v)$(HOST_CC) $(WARNFLAGS) $(CFLAGS) -c -o $@ $<
	@echo HOST_CC $@

parser.c: parser.y
	$(_v)$(HOST_BISON) -y -d -d -o $@ $<
	@echo HOST_BISON $@

lexer.yy.c: lexer.l
	$(_v)$(HOST_FLEX) --header-file=lexer.yy.h -o $@ $<
	@echo HOST_FLEX $@

main.o mkglue.o mkheaders.o mkioconf.o mkmakefile.o lexer.yy.c: parser.c

do_build_setup: config

include $(MakeInc_rule)
include $(MakeInc_dir)
