SDKROOT ?= /
ifeq "$(RC_TARGET_CONFIG)" "iPhone"
Embedded?=YES
else
Embedded?=$(shell echo $(SDKROOT) | grep -iq iphoneos && echo YES || echo NO)
endif

ifdef RC_ARCHS
    ARCHS:=$(RC_ARCHS)
  else
    ifeq "$(Embedded)" "YES"
      ARCHS:=armv7 armv7s arm64
    else
      ARCHS:=x86_64 i386
  endif
endif

CC = $(shell xcrun -sdk "$(SDKROOT)" -find cc)
STRIP = $(shell xcrun -sdk "$(SDKROOT)" -find strip)
CODESIGN = $(shell xcrun -sdk "$(SDKROOT)" -find codesign)
export CODESIGN_ALLOCATE := $(shell xcrun -sdk "$(SDKROOT)" -find codesign_allocate)
DSYMUTIL = $(shell xcrun -sdk "$(SDKROOT)" -find dsymutil)
CFLAGS = -O0 -g -isysroot $(SDKROOT) $(patsubst %, -arch %,$(ARCHS))
LDFLAGS = -dead_strip \
	-isysroot $(SDKROOT) $(patsubst %, -arch %,$(ARCHS))

OBJROOT?=$(shell /bin/pwd)/BUILD/obj
SYMROOT?=$(shell /bin/pwd)/BUILD/sym
DSTROOT?=$(shell /bin/pwd)/BUILD/dst

EXECUTABLES = exit.nodyld \
	exit.nopie.dyld-but-no-Libsystem exit.pie.dyld-but-no-Libsystem \
	exit.nopie.dyld-and-Libsystem exit.pie.dyld-and-Libsystem \
	exit.nopie exit.pie \
	printexecinfo run test
OBJECTS = exit-asm.o exit.o printexecinfo.o run.o

default: $(addprefix $(DSTROOT)/,$(EXECUTABLES))

clean:
	rm -f $(addprefix $(OBJROOT)/,$(OBJECTS))
	rm -f $(addprefix $(SYMROOT)/,$(EXECUTABLES))
	rm -rf $(addsuffix .dSYM,$(addprefix $(SYMROOT)/,$(EXECUTABLES)))
	rm -f $(addprefix $(DSTROOT)/,$(EXECUTABLES))

# DEPENDENCIES
$(addprefix $(DSTROOT)/,$(EXECUTABLES)): DSTROOT SYMROOT

$(addprefix $(OBJROOT)/,$(OBJECTS)): OBJROOT

DSTROOT SYMROOT OBJROOT:
	mkdir -p $($@)

# OBJECTS

$(OBJROOT)/exit-asm.o: exit-asm.S OBJROOT
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJROOT)/exit.o: exit.c OBJROOT
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJROOT)/printexecinfo.o: printexecinfo.c OBJROOT
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJROOT)/run.o: run.c OBJROOT
	$(CC) -c -o $@ $< $(CFLAGS)

# EXECUTABLES

$(DSTROOT)/exit.nodyld: $(OBJROOT)/exit-asm.o
	$(CC) -o $@ $< $(LDFLAGS) -e _main -nostartfiles -nodefaultlibs -static -Wl,-segalign,0x4000
	$(CODESIGN) -s - $@

$(DSTROOT)/exit.nopie.dyld-but-no-Libsystem: $(OBJROOT)/exit-asm.o
	$(CC) -o $@ $< $(LDFLAGS) -e _main -Wl,-no_pie -nostartfiles -nodefaultlibs -Wl,-no_new_main
	$(CODESIGN) -s - $@

$(DSTROOT)/exit.pie.dyld-but-no-Libsystem: $(OBJROOT)/exit-asm.o
	$(CC) -o $@ $< $(LDFLAGS) -e _main -Wl,-pie -nostartfiles -nodefaultlibs -Wl,-no_new_main
	$(CODESIGN) -s - $@

$(DSTROOT)/exit.nopie.dyld-and-Libsystem: $(OBJROOT)/exit-asm.o
	$(CC) -o $@ $< $(LDFLAGS) -Wl,-no_pie -nostartfiles -nodefaultlibs -lSystem
	$(CODESIGN) -s - $@

$(DSTROOT)/exit.pie.dyld-and-Libsystem: $(OBJROOT)/exit-asm.o
	$(CC) -o $@ $< $(LDFLAGS) -Wl,-pie -nostartfiles -nodefaultlibs -lSystem
	$(CODESIGN) -s - $@

$(DSTROOT)/exit.nopie: $(OBJROOT)/exit.o
	$(CC) -o $@ $< $(LDFLAGS) -Wl,-no_pie
	$(CODESIGN) -s - $@

$(DSTROOT)/exit.pie: $(OBJROOT)/exit.o
	$(CC) -o $@ $< $(LDFLAGS) -Wl,-pie
	$(CODESIGN) -s - $@

$(DSTROOT)/printexecinfo: $(OBJROOT)/printexecinfo.o
	$(CC) -o $@ $< $(LDFLAGS)
	$(CODESIGN) -s - $@

$(DSTROOT)/run: $(OBJROOT)/run.o
	$(CC) -o $(SYMROOT)/run $< $(LDFLAGS)
	$(DSYMUTIL) $(SYMROOT)/run
	$(STRIP) -S -o $@ $(SYMROOT)/run
	$(CODESIGN) -s - $@

$(DSTROOT)/test: test.sh
	install -m 755 $< $@
