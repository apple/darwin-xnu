#!/usr/bin/make

DSTROOT?=$(shell /bin/pwd)
CC:=clang
CFLAGS:=-I.

ifdef RC_ARCHS
    ARCH:=$(RC_ARCHS)
  else
    ifeq "$(Embedded)" "YES"
      ARCH:=armv7 armv7s
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

all: $(DSTROOT)/memorystatus

$(DSTROOT)/memorystatus: memorystatus.c
	xcrun -sdk $(SDKROOT) $(CC) $(MY_ARCH) -framework CoreFoundation -framework ServiceManagement -F $(SDKROOT)/System/Library/PrivateFrameworks/ -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders -o $@ memorystatus.c $(CFLAGS)
	codesign -f -s - $@

clean: 
	rm -f $(DSTROOT)/memorystatus
