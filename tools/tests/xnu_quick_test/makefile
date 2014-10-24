SDKROOT ?= /

PLATFORMPATH := $(shell xcrun -sdk $(SDKROOT) -show-sdk-platform-path)
PLATFORM := $(shell echo $(PLATFORMPATH) | sed 's,^.*/\([^/]*\)\.platform$$,\1,')
SDKVERSION:=$(shell xcodebuild -sdk $(SDKROOT) -version SDKVersion | head -1)
SDKPATH := $(shell xcodebuild -sdk $(SDKROOT) -version Path)

ifneq ($(filter iPhoneOS iPhoneOSNano,$(PLATFORM)),)
CFLAGS += -isysroot $(SDKPATH) -miphoneos-version-min=$(SDKVERSION)
LIBFLAGS += -isysroot $(SDKPATH) -miphoneos-version-min=$(SDKVERSION)
else
CFLAGS += -mmacosx-version-min=$(SDKVERSION)
LIBFLAGS += -mmacosx-version-min=$(SDKVERSION)
endif

CC := $(shell xcrun -sdk "$(SDKROOT)" -find cc)
HOSTCC := cc

CODESIGN := $(shell xcrun -sdk "$(SDKROOT)" -find codesign)

SRCROOT?=$(shell /bin/pwd)
OBJROOT?=$(SRCROOT)/BUILD/obj
DSTROOT?=$(SRCROOT)/BUILD/dst
SYMROOT?=$(SRCROOT)/BUILD/sym

SRCSUBPATH := $(SRCROOT)
OBJSUBPATH := $(OBJROOT)

ifdef RC_ARCHS
  ARCH:=$(RC_ARCHS)
else
  ifeq ($(PLATFORM),MacOSX)
    ARCH:=i386 x86_64
  else ifneq ($(filter iPhoneOS iPhoneOSNano,$(PLATFORM)),)
    ARCH:=arm64 armv7s armv7
endif
endif

MY_ARCH := $(patsubst %, -arch %, $(ARCH)) # allows building multiple archs.
ARCH_32 := $(filter-out %64, $(ARCH))
ARCH_32_FLAGS := $(patsubst %, -arch %, $(ARCH_32))
ARCH_64 := $(filter %64, $(ARCH))
ARCH_64_FLAGS := $(patsubst %, -arch %, $(ARCH_64))

CFLAGS += -g -I $(SDKPATH)/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders/ -F/AppleInternal/Library/Frameworks/ $(MORECFLAGS) -Wno-deprecated-declarations

LIBFLAGS += -I $(SDKPATH)/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders  -F/AppleInternal/Library/Frameworks/ 

# The current implementation of the content protection test requires IOKit.
ifneq ($(filter iPhoneOS iPhoneOSNano,$(PLATFORM)),)
LIBFLAGS += -framework IOKit
endif

MY_OBJECTS := $(OBJSUBPATH)/main.o $(OBJSUBPATH)/memory_tests.o $(OBJSUBPATH)/misc.o \
			 $(OBJSUBPATH)/sema_tests.o $(OBJSUBPATH)/shared_memory_tests.o \
			 $(OBJSUBPATH)/socket_tests.o $(OBJSUBPATH)/tests.o \
			 $(OBJSUBPATH)/xattr_tests.o $(OBJSUBPATH)/kqueue_tests.o \
			 $(OBJSUBPATH)/machvm_tests.o $(OBJSUBPATH)/commpage_tests.o \
			 $(OBJSUBPATH)/atomic_fifo_queue_test.o $(OBJSUBPATH)/sched_tests.o \
			 $(OBJSUBPATH)/pipes_tests.o

ifeq ($(PLATFORM),MacOSX)
MY_OBJECTS += $(OBJSUBPATH)/32bit_inode_tests.o
endif

ifneq ($(filter iPhoneOS iPhoneOSNano,$(PLATFORM)),)
MY_OBJECTS += $(OBJSUBPATH)/content_protection_test.o
endif


xnu_quick_test : $(OBJSUBPATH) $(DSTROOT) $(SYMROOT) $(MY_OBJECTS) helpers
ifndef RC_ProjectName
	rm -rf $(DSTROOT)/xnu_quick_test
endif
	$(CC) -g $(MY_ARCH) $(LIBFLAGS) -o $(SYMROOT)/xnu_quick_test $(MY_OBJECTS)
	/usr/bin/dsymutil $(SYMROOT)/xnu_quick_test
ifneq ($(filter iPhoneOS iPhoneOSNano,$(PLATFORM)),)
	$(CODESIGN) -f -s - --entitlements $(SRCSUBPATH)/xnu_quick_test.entitlements $(SYMROOT)/xnu_quick_test
endif
	/usr/bin/ditto $(SYMROOT)/xnu_quick_test $(DSTROOT)/xnu_quick_test

# This target is defined for testbots. 
# Before compiling this target, MORECFLAGS must be set to "-D RUN_UNDER_TESTBOTS=1", check README file for more details
# NOTE: -f[ailures] MAX_FAILS_ALLOWED option is set to 100 to make sure we completely run the test suite and 
# report all the failures.

testbots: xnu_quick_test 
	@(cd $(DSTROOT) ; ./xnu_quick_test -f 100)

# The helper binaries are used to test exec()'ing between 64bit and 32bit. 
# Creates test binaries with page zero sizes = 4KB and 4GB. Also creates 32-bit
# helper processes for the 64-bit version of xnu_quick_test to test the conversion
# from a 32-bit process to a 64-bit process.
helpers : $(SRCSUBPATH)/helpers/sleep.c $(SRCSUBPATH)/helpers/launch.c $(SRCSUBPATH)/helpers/arch.c $(SRCSUBPATH)/helpers/data_exec.c helperdir $(OBJSUBPATH)/misc.o
ifeq ($(PLATFORM),MacOSX)
ifneq "$(ARCH_32)" ""
	$(CC) -g $(ARCH_32_FLAGS)                              $(SRCSUBPATH)/helpers/sleep.c -o $(SYMROOT)/sleep-i386
	/usr/bin/ditto $(SYMROOT)/sleep-i386 $(DSTROOT)/helpers/
endif
endif
ifeq ($(PLATFORM),MacOSX)
ifneq "$(ARCH_32)" ""
	$(CC) -g $(LIBFLAGS) $(ARCH_32_FLAGS)	$(OBJSUBPATH)/misc.o $(SRCSUBPATH)/helpers/launch.c -o $(SYMROOT)/launch-i386
	$(CC) -g $(ARCH_32_FLAGS) 	-DNXDATA32TESTNONX $(SRCSUBPATH)/helpers/data_exec.c -o $(SYMROOT)/data_exec32nonxspawn
	/usr/bin/ditto $(SYMROOT)/launch-i386 $(SYMROOT)/data_exec32nonxspawn $(DSTROOT)/helpers/
endif
ifneq "$(ARCH_64)" ""
	$(CC) -g $(ARCH_64_FLAGS) -pagezero_size 0x100000000 $(SRCSUBPATH)/helpers/sleep.c -o $(SYMROOT)/sleep-x86_64-4G
	$(CC) -g $(ARCH_64_FLAGS) -pagezero_size 0x1000      $(SRCSUBPATH)/helpers/sleep.c -o $(SYMROOT)/sleep-x86_64-4K
	$(CC) -g $(LIBFLAGS) $(ARCH_64_FLAGS)	$(OBJSUBPATH)/misc.o $(SRCSUBPATH)/helpers/launch.c -o $(SYMROOT)/launch-x86_64
	/usr/bin/ditto $(SYMROOT)/sleep-x86_64-4G $(SYMROOT)/sleep-x86_64-4K $(SYMROOT)/launch-x86_64 $(DSTROOT)/helpers/
endif
	$(CC) -g $(MY_ARCH) 	$(SRCSUBPATH)/helpers/data_exec.c -o $(SYMROOT)/data_exec
	/usr/bin/ditto $(SYMROOT)/data_exec $(DSTROOT)/helpers/
endif
ifneq ($(filter iPhoneOS iPhoneOSNano,$(PLATFORM)),)
ifneq "$(ARCH_32)" ""
	$(CC) $(CFLAGS) $(ARCH_32_FLAGS) $(SRCSUBPATH)/helpers/sleep.c -o $(SYMROOT)/sleep-arm
	$(CC) $(LIBFLAGS) $(CFLAGS) $(ARCH_32_FLAGS) $(OBJSUBPATH)/misc.o $(SRCSUBPATH)/helpers/launch.c -o $(SYMROOT)/launch-arm
	/usr/bin/ditto $(SYMROOT)/sleep-arm $(SYMROOT)/launch-arm $(DSTROOT)/helpers/
endif
ifneq "$(ARCH_64)" ""
	$(CC) $(CFLAGS) $(ARCH_64_FLAGS) $(SRCSUBPATH)/helpers/sleep.c -o $(SYMROOT)/sleep-arm64
	/usr/bin/ditto $(SYMROOT)/sleep-arm64 $(DSTROOT)/helpers/
endif
endif
	$(CC) -g $(MY_ARCH) $(CFLAGS) $(SRCSUBPATH)/helpers/arch.c -o $(SYMROOT)/arch
	/usr/bin/ditto $(SYMROOT)/arch $(DSTROOT)/helpers/

helperdir :
	mkdir -p $(DSTROOT)/helpers

$(OBJSUBPATH) :
	mkdir -p $(OBJSUBPATH);

$(DSTROOT) :
	mkdir -p $(DSTROOT);

$(SYMROOT) :
	mkdir -p $(SYMROOT)

$(OBJSUBPATH)/main.o : $(SRCSUBPATH)/main.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/main.c  -o $@

$(OBJSUBPATH)/memory_tests.o : $(SRCSUBPATH)/memory_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/memory_tests.c  -o $@

# misc.o has to be built 3-way for the helpers to link
$(OBJSUBPATH)/misc.o : $(SRCSUBPATH)/misc.c $(SRCSUBPATH)/tests.h
ifneq ($(filter iPhoneOS iPhoneOSNano,$(PLATFORM)),)
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/misc.c   -o $@
else
	$(CC) -arch i386 -arch x86_64 $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/misc.c   -o $@
endif

$(OBJSUBPATH)/sema_tests.o : $(SRCSUBPATH)/sema_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/sema_tests.c   -o $@

$(OBJSUBPATH)/shared_memory_tests.o : $(SRCSUBPATH)/shared_memory_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/shared_memory_tests.c   -o $@

$(OBJSUBPATH)/socket_tests.o : $(SRCSUBPATH)/socket_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/socket_tests.c   -o $@

$(OBJSUBPATH)/tests.o : $(SRCSUBPATH)/tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/tests.c    -o $@

$(OBJSUBPATH)/xattr_tests.o : $(SRCSUBPATH)/xattr_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/xattr_tests.c    -o $@

$(OBJSUBPATH)/machvm_tests.o : $(SRCSUBPATH)/machvm_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/machvm_tests.c    -o $@

$(OBJSUBPATH)/sched_tests.o : $(SRCSUBPATH)/sched_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/sched_tests.c    -o $@

$(OBJSUBPATH)/kqueue_tests.o : $(SRCSUBPATH)/kqueue_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/kqueue_tests.c   -o $@

$(OBJSUBPATH)/32bit_inode_tests.o : $(SRCSUBPATH)/32bit_inode_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/32bit_inode_tests.c    -o $@

$(OBJSUBPATH)/commpage_tests.o : $(SRCSUBPATH)/commpage_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/commpage_tests.c    -o $@

$(OBJSUBPATH)/atomic_fifo_queue_test.o : $(SRCSUBPATH)/atomic_fifo_queue_test.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/atomic_fifo_queue_test.c    -o $@

$(OBJSUBPATH)/content_protection_test.o : $(SRCSUBPATH)/content_protection_test.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/content_protection_test.c -o $@

$(OBJSUBPATH)/pipes_tests.o : $(SRCSUBPATH)/pipes_tests.c $(SRCSUBPATH)/tests.h
	$(CC) $(CFLAGS) $(MY_ARCH) -c $(SRCSUBPATH)/pipes_tests.c -o $@

.PHONY : clean
clean :
	rm -Rf $(DSTROOT)/xnu_quick_test
	rm -Rf $(DSTROOT)/helpers/*
	rm -Rf $(OBJSUBPATH)/*.o
