################################################################################
# Note: this makefile is used only for the libkxld build alias.  It is not part
# of the regular kernel build process.
################################################################################

# Version
COMPATIBILITY_VERSION=1
CURRENT_VERSION=1

# Paths
ifndef DSTROOT
DSTROOT=./BUILD/dst
endif
ifndef OBJROOT
OBJROOT=./BUILD/obj
endif
ifndef SYMROOT
SYMROOT=./BUILD/sym
endif
ifdef SRCROOT
EXTHDRSRC=$(SRCROOT)/EXTERNAL_HEADERS
HDRSRC=$(SRCROOT)/libkern/libkern
OBJSRC=$(SRCROOT)/libkern/kxld
else
SRCROOT=.
EXTHDRSRC=$(SRCROOT)/../../EXTERNAL_HEADERS
HDRSRC=$(SRCROOT)/../libkern
OBJSRC=$(SRCROOT)
ROOT=BUILD
endif
ifdef RC_CFLAGS
ARCHS=$(addprefix -arch , $(RC_ARCHS))
else
ARCHS=-arch x86_64
RC_CFLAGS=$(ARCHS) -pipe
endif
ifdef INSTALL_LOCATION
override DSTROOT := $(DSTROOT)/$(INSTALL_LOCATION)
endif

PRODUCT_TYPE ?= DYLIB

HDRDST=$(DSTROOT)/usr/local/include
DYLIBDST=$(DSTROOT)/usr/lib/system
ARCHIVEDST=$(DSTROOT)/usr/local/lib
LIBKXLD_DYLIB=libkxld.dylib
LIBKXLD_ARCHIVE=libkxld.a
LIBKXLD_DSYM=$(LIBKXLD_DYLIB).dSYM
LIBKXLD_INSTALLNAME=/usr/lib/system/$(LIBKXLD_DYLIB)
LIBKXLDOBJ_DYLIB=$(OBJROOT)/$(LIBKXLD_DYLIB)
LIBKXLDOBJ_ARCHIVE=$(OBJROOT)/$(LIBKXLD_ARCHIVE)
LIBKXLDSYM_DYLIB=$(SYMROOT)/$(LIBKXLD_DYLIB)
LIBKXLDSYM_DYLIB_DSYM=$(SYMROOT)/$(LIBKXLD_DSYM)
LIBKXLDSYM_ARCHIVE=$(SYMROOT)/$(LIBKXLD_ARCHIVE)
LIBKXLDDST_DYLIB=$(DYLIBDST)/$(LIBKXLD_DYLIB)
LIBKXLDDST_ARCHIVE=$(ARCHIVEDST)/$(LIBKXLD_ARCHIVE)
TESTSRC=$(SRCROOT)/tests
TESTDST=./BUILD/tests

# Flags
ifdef SDKROOT
	SDK_DIR := $(shell xcodebuild -version -sdk $(SDKROOT) Path)
endif

ifeq ($(strip $(SDK_DIR)),)
	SDK_DIR := /
endif

DEFINES = -DPRIVATE
CFLAGS=-std=c99 -Wall -Wextra -Werror -pedantic -Wformat=2 -Wcast-align \
	-Wwrite-strings -Wshorten-64-to-32 -Wshadow -Winit-self -Wpointer-arith \
	-Wno-format-y2k -W -Wstrict-prototypes -Wmissing-prototypes -Wreturn-type \
	-Wcast-qual -Wwrite-strings -Wswitch -Wcast-align -Wbad-function-cast \
	-Wchar-subscripts -Winline -Wnested-externs -Wredundant-decls -g
LDFLAGS=$(ARCHS) -dynamiclib -install_name $(LIBKXLD_INSTALLNAME) \
	-compatibility_version $(COMPATIBILITY_VERSION) \
	-current_version $(CURRENT_VERSION) -lstdc++
INCLUDES=-I$(HDRSRC) -isystem $(EXTHDRSRC)

ifneq ($(SDK_DIR),/)
	CFLAGS += -isysroot $(SDK_DIR)
	LDFLAGS += -isysroot $(SDK_DIR)
endif

# Tools
CC = xcrun -sdk $(SDK_DIR) clang
CLANG_ANALYZER = clang --analyze
LIBTOOL = xcrun -sdk $(SDK_DIR) libtool
STRIP = xcrun -sdk $(SDK_DIR) strip
DSYMUTIL = xcrun -sdk $(SDK_DIR) dsymutil

# Files
HDR_NAMES=kxld.h kxld_types.h
OBJ_NAMES=kxld.o kxld_array.o kxld_copyright.o kxld_demangle.o kxld_dict.o \
	kxld_kext.o kxld_object.o kxld_reloc.o kxld_sect.o kxld_seg.o	   \
	kxld_srcversion.o kxld_sym.o kxld_symtab.o kxld_util.o kxld_uuid.o \
    kxld_vtable.o kxld_versionmin.o

HDRS=$(addprefix $(HDRSRC)/, $(HDR_NAMES))
OBJS=$(addprefix $(OBJROOT)/, $(OBJ_NAMES))

$(shell [ -d $(OBJROOT) ] || mkdir -p $(OBJROOT))

# Implicit rules
%.o : %.c
$(OBJROOT)/%.o : $(OBJSRC)/%.c
	$(CC) $(RC_CFLAGS) $(CFLAGS) $(DEFINES) $(OPTIM) $(INCLUDES) -c $< -o $@
$(OBJROOT)/%.o : $(TESTSRC)/%.c
	$(CC) $(RC_CFLAGS) $(CFLAGS) $(DEFINES) -O0 -DDEBUG $(INCLUDES) -I $(SRCROOT) -c $< -o $@

SRCROOTESC=$(subst /,\/,$(SRCROOT))
OBJROOTESC=$(subst /,\/,$(OBJROOT))
SEDOBJS=sed -E 's/(^[a-z_]+)\.o/$(OBJROOTESC)\/\1\.o $(OBJROOTESC)\/\1\.d/'
SEDSRCS=sed -E 's/ ([a-z_]+\.[ch])/ $(SRCROOTESC)\/\1/g'
$(OBJROOT)/%.d: $(OBJSRC)/%.c
	@set -e; rm -f $@; \
	$(CC) $(INCLUDES) -MM $< | $(SEDOBJS) | $(SEDSRCS) > $@;

# Rules
release: OPTIM=-Os -dynamic
release: build

debug: OPTIM=-O0 -DDEBUG -dynamic
debug: build

profile: OPTIM=-Os -pg -dynamic
profile: build

tests: OPTIM=-O0 -DDEBUG
tests: kxld_array_test kxld_dict_test copyrighttest

build: $(LIBKXLDSYM_$(PRODUCT_TYPE))

$(LIBKXLDSYM_DYLIB): $(LIBKXLDOBJ_DYLIB)
	@mkdir -p $(SYMROOT)
	install -c -m 644 $< $@
	$(DSYMUTIL) $@ -o $(LIBKXLDSYM_DYLIB_DSYM)

$(LIBKXLDSYM_ARCHIVE): $(LIBKXLDOBJ_ARCHIVE)
	@mkdir -p $(SYMROOT)
	install -c -m 644 $< $@

$(LIBKXLDOBJ_DYLIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(LIBKXLDOBJ_ARCHIVE): $(OBJS)
	$(LIBTOOL) -static -o $@ $^

installhdrs:
	@mkdir -p $(HDRDST)
	install -o 0 -g 0 -c -m 444 $(HDRS) $(HDRDST)

install: release installhdrs $(LIBKXLDDST_$(PRODUCT_TYPE))

$(LIBKXLDDST_DYLIB): $(LIBKXLDSYM_DYLIB)
	@mkdir -p $(DYLIBDST)
	install -o 0 -g 0 -c -m 555 $< $@
	$(STRIP) -S -x $@

$(LIBKXLDDST_ARCHIVE): $(LIBKXLDSYM_ARCHIVE)
	@mkdir -p $(ARCHIVEDST)
	install -o 0 -g 0 -c -m 555 $< $@


KEXTCOPYOBJS=$(OBJROOT)/kextcopyright.o $(OBJROOT)/kxld_copyright.o $(OBJROOT)/kxld_util.o 
kextcopyright: $(TESTDST)/kextcopyright
$(TESTDST)/kextcopyright: $(KEXTCOPYOBJS)
	@mkdir -p $(TESTDST)
	$(CC) $(ARCHS) $(KEXTCOPYOBJS) -framework CoreFoundation -o $(OBJROOT)/kextcopyright
	install -c -m 755 $(OBJROOT)/kextcopyright $@

TESTOBJS=$(OBJROOT)/kxld_test.o $(OBJROOT)/kxld_util.o

ARRAYOBJS=$(OBJROOT)/kxld_array_test.o $(OBJROOT)/kxld_array.o $(TESTOBJS)
kxld_array_test: $(TESTDST)/kxld_array_test
$(TESTDST)/kxld_array_test: $(ARRAYOBJS)
	@mkdir -p $(TESTDST)
	$(CC) $(ARCHS) $(ARRAYOBJS) -o $(OBJROOT)/kxld_array_test
	install -c -m 755 $(OBJROOT)/kxld_array_test $@

DICTOBJS=$(OBJROOT)/kxld_dict_test.o $(OBJROOT)/kxld_dict.o $(OBJROOT)/kxld_array.o $(TESTOBJS)
kxld_dict_test: $(TESTDST)/kxld_dict_test
$(TESTDST)/kxld_dict_test: $(DICTOBJS)
	@mkdir -p $(TESTDST)
	$(CC) $(ARCHS) $(DICTOBJS) -o $(OBJROOT)/kxld_dict_test
	install -c -m 755 $(OBJROOT)/kxld_dict_test $@

COPYTESTOBJS=$(OBJROOT)/kxld_copyright.o $(OBJROOT)/kxld_util.o
copyrighttest: OPTIM+=-DTEST
copyrighttest: $(TESTDST)/copyrighttest
$(TESTDST)/copyrighttest: $(COPYTESTOBJS)
	@mkdir -p $(TESTDST)
	$(CC) $(ARCHS) $(COPYTESTOBJS) -framework CoreFoundation -framework IOKit -o $(OBJROOT)/copyrighttest
	install -c -m 755 $(OBJROOT)/copyrighttest $@

analyze:
	@$(CLANG_ANALYZER) *.c
	@$(CLANG_ANALYZER) -I. tests/*.c
	@rm -f *.plist

clean: 
	@rm -rf $(OBJROOT)/*

fullclean:
ifdef ROOT
	@rm -rf $(ROOT)
else
	@rm -rf $(OBJROOT) $(DSTROOT) $(SYMROOT)
endif

# Automatically build dependency information when .c or .h files change based
# on implicit rule for .d:.c
-include $(OBJS:.o=.d)

