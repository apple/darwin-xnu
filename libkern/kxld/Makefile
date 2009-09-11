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
HDRSRC=$(SRCROOT)/libkern/libkern
OBJSRC=$(SRCROOT)/libkern/kxld
else
SRCROOT=.
HDRSRC=$(SRCROOT)/../libkern
OBJSRC=$(SRCROOT)
ROOT=BUILD
endif
ifdef RC_CFLAGS
ARCHS=$(addprefix -arch , $(RC_ARCHS))
else
ARCHS=-arch i386 -arch x86_64 -arch ppc
RC_CFLAGS=$(ARCHS) -pipe
endif

PRODUCT_TYPE ?= DYLIB

HDRDST=$(DSTROOT)/usr/local/include
LIBDST=$(DSTROOT)/usr/lib/system
ARCHIVEDST=$(DSTROOT)/usr/local/lib
LIBOBJ=$(OBJROOT)/libkxld.o
LIBKXLD_DYLIB=libkxld.dylib
LIBKXLD_ARCHIVE=libkxld.a
LIBKXLDNAME=/usr/lib/system/$(LIBKXLD_DYLIB)
LIBKXLDOBJ_DYLIB=$(OBJROOT)/$(LIBKXLD_DYLIB)
LIBKXLDOBJ_ARCHIVE=$(OBJROOT)/$(LIBKXLD_ARCHIVE)
LIBKXLDDST_DYLIB=$(LIBDST)/$(LIBKXLD_DYLIB)
LIBKXLDDST_ARCHIVE=$(ARCHIVEDST)/$(LIBKXLD_ARCHIVE)
TESTSRC=$(SRCROOT)/tests
TESTDST=./BUILD/tests

# Flags
SDKROOT ?= /
CFLAGS=-std=c99 -Wall -Wextra -Werror -pedantic -Wformat=2 -Wcast-align \
	-Wwrite-strings -Wshorten-64-to-32 -Wshadow -Winit-self -Wpointer-arith \
	-Wno-format-y2k -W -Wstrict-prototypes -Wmissing-prototypes -Wreturn-type \
	-Wcast-qual -Wwrite-strings -Wswitch -Wcast-align -Wbad-function-cast \
	-Wchar-subscripts -Winline -Wnested-externs -Wredundant-decls -g \
	-isysroot $(SDKROOT)
LDFLAGS=$(ARCHS) -dynamiclib -install_name $(LIBKXLDNAME) \
	-compatibility_version $(COMPATIBILITY_VERSION) \
	-current_version $(CURRENT_VERSION) -isysroot $(SDKROOT)
INCLUDES=-I$(HDRSRC) $(INCFLAGS_EXTERN)

# Tools
CC = xcrun -sdk $(SDKROOT) cc
LIBTOOL = xcrun -sdk $(SDKROOT) libtool
STRIP = xcrun -sdk $(SDKROOT) strip

# Turn on -Wno-cast-align for arm since it won't build without it
ifeq ($(findstring arm, $(ARCHS)),arm)
CFLAGS+=-Wno-cast-align 
endif

# Files
HDR_NAMES=kxld.h kxld_types.h
OBJ_NAMES=kxld.o kxld_array.o kxld_copyright.o kxld_dict.o kxld_kext.o kxld_reloc.o \
	kxld_sect.o kxld_seg.o kxld_sym.o kxld_state.o kxld_symtab.o kxld_util.o \
	kxld_uuid.o kxld_vtable.o
HDRS=$(addprefix $(HDRSRC)/, $(HDR_NAMES))
OBJS=$(addprefix $(OBJROOT)/, $(OBJ_NAMES))

$(shell [ -d $(OBJROOT) ] || mkdir -p $(OBJROOT))

# Implicit rules
%.o : %.c
$(OBJROOT)/%.o : $(OBJSRC)/%.c
	$(CC) $(RC_CFLAGS) $(CFLAGS) $(OPTIM) $(INCLUDES) -c $< -o $@
$(OBJROOT)/%.o : $(TESTSRC)/%.c
	$(CC) $(RC_CFLAGS) $(CFLAGS) -O0 -DDEBUG $(INCLUDES) -I $(SRCROOT) -c $< -o $@

SRCROOTESC=$(subst /,\/,$(SRCROOT))
OBJROOTESC=$(subst /,\/,$(OBJROOT))
SEDOBJS=sed -E 's/(^[a-z_]+)\.o/$(OBJROOTESC)\/\1\.o $(OBJROOTESC)\/\1\.d/'
SEDSRCS=sed -E 's/([a-z_]+\.[ch])/$(SRCROOTESC)\/\1/g'
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
tests: kxld_dict_test copyrighttest

build: $(LIBKXLDOBJ_$(PRODUCT_TYPE))
	@[ -d $(SYMROOT) ] || mkdir -p $(SYMROOT)
	install -c -m 644 $< $(SYMROOT)

$(LIBKXLDOBJ_DYLIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(LIBKXLDOBJ_ARCHIVE): $(OBJS)
	$(LIBTOOL) -static -o $@ $^

installhdrs:
	@[ -d $(HDRDST) ] || mkdir -p $(HDRDST)
	install -o 0 -g 0 -c -m 444 $(HDRS) $(HDRDST)

install: release installhdrs $(LIBKXLDDST_$(PRODUCT_TYPE))

$(LIBKXLDDST_DYLIB):
	@[ -d $(LIBDST) ] || mkdir -p $(LIBDST)
	install -o 0 -g 0 -c -m 555 $(SYMROOT)/$(LIBKXLD_DYLIB) $(LIBDST)
	$(STRIP) -S -x $@

$(LIBKXLDDST_ARCHIVE):
	@[ -d $(ARCHIVEDST) ] || mkdir -p $(ARCHIVEDST)
	install -o 0 -g 0 -c -m 555 $(SYMROOT)/$(LIBKXLD_ARCHIVE) $(ARCHIVEDST)


KEXTCOPYOBJS=$(OBJROOT)/kextcopyright.o $(OBJROOT)/kxld_copyright.o $(OBJROOT)/kxld_util.o 
kextcopyright: $(KEXTCOPYOBJS) $(TESTDST)
	$(CC) $(ARCHS) $(KEXTCOPYOBJS) -framework CoreFoundation -o $(OBJROOT)/kextcopyright
	install -c -m 755 $(OBJROOT)/kextcopyright $(TESTDST)

DICTOBJS=$(OBJROOT)/kxld_dict_test.o $(OBJROOT)/kxld_dict.o $(OBJROOT)/kxld_array.o $(OBJROOT)/kxld_util.o
kxld_dict_test: $(DICTOBJS) $(TESTDST)
	$(CC) $(ARCHS) $(DICTOBJS) -o $(OBJROOT)/kxld_dict_test
	install -c -m 755 $(OBJROOT)/kxld_dict_test $(TESTDST)

COPYTESTOBJS=$(OBJROOT)/kxld_copyright.o $(OBJROOT)/kxld_util.o
copyrighttest: OPTIM+=-DTEST
copyrighttest: $(KEXTCOPYOBJS) $(TESTDST)
	$(CC) $(ARCHS) $(COPYTESTOBJS) -framework CoreFoundation -framework IOKit -o $(OBJROOT)/copyrighttest
	install -c -m 755 $(OBJROOT)/copyrighttest $(TESTDST)

$(TESTDST):
	@[ -d $(TESTDST) ] || mkdir -p $(TESTDST)

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

