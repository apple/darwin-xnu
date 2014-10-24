#!/usr/bin/make

DSTROOT?=$(shell /bin/pwd)
CC:=$(shell xcrun -sdk "$(SDKROOT)" -find clang)
CFLAGS:=-I. -g

ifdef RC_ARCHS
    ARCH:=$(RC_ARCHS)
  else
    ifeq "$(Embedded)" "YES"
      ARCH:=armv7 armv7s arm64
    else
      ARCH:=x86_64 i386
  endif
endif

ifeq "$(RC_TARGET_CONFIG)" "iPhone"
Embedded?=YES
else
Embedded?=$(shell echo $(SDKROOT) | grep -iq iphoneos && echo YES || echo NO)
endif

ifeq "$(Embedded)" "NO"
    SDKROOT:=$(shell xcodebuild -sdk macosx.internal -version Path)
else
    SDKROOT:=$(shell xcodebuild -sdk iphoneos.internal -version Path)
endif

MY_ARCH := $(patsubst %, -arch %, $(ARCH)) # allows building multiple archs.

all: $(DSTROOT)/memorystatus \
	$(DSTROOT)/memorystatus_groups

$(DSTROOT)/memorystatus_groups: memorystatus_groups.c
	$(CC) $(MY_ARCH)  -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders -o $(SYMROOT)/$(notdir $@) memorystatus_groups.c $(CFLAGS)
	ditto $(SYMROOT)/$(notdir $@) $@
	codesign -f -s - $@


$(DSTROOT)/memorystatus: memorystatus.c
	$(CC) $(MY_ARCH) -framework CoreFoundation -framework ServiceManagement -F $(SDKROOT)/System/Library/PrivateFrameworks/ -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders -o $(SYMROOT)/$(notdir $@) memorystatus.c $(CFLAGS)
	ditto $(SYMROOT)/$(notdir $@) $@
	codesign -f -s - $@

clean: 
	rm -f $(DSTROOT)/memorystatus
	rm -f $(DSTROOT)/memorystatus_groups
