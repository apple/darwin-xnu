ifndef SDKROOT
SDKROOT := macosx.internal
endif

SDKPATH := $(shell xcrun -sdk $(SDKROOT) -show-sdk-path)

ifndef SRCROOT
	SRCROOT := $(CURDIR)/../..
endif

ifndef OBJROOT
    OBJROOT:=$(CURDIR)
endif

ARCHES := $(shell file $(SDKPATH)/usr/lib/libc.dylib | perl -lne 'print "-arch $$1" if /for architecture ([\w_]+)/')

CFLAGS := $(ARCHES) -I $(SDKPATH)/System/Library/Frameworks/System.framework/PrivateHeaders

# -I $(SRCROOT)/kcdata -iprefix kern/ -iwithprefix $(SRCROOT)/osfmk/kern
#-I $(SRCROOT)/bsd
#

$(OBJROOT)/stackshot: stackshot.c
	xcrun -sdk $(SDKROOT) clang $(CFLAGS) $< -o $@
