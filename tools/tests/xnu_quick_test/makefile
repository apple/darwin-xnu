SDKROOT ?= /
Product=$(shell tconf --product)
Embedded=$(shell tconf --test TARGET_OS_EMBEDDED)

SDKVERSION=$(shell xcodebuild -sdk $(SDKROOT) -version SDKVersion | head -1)

ifeq "$(Embedded)" "YES"
XILogFLAG =
SDKPATH = $(shell xcodebuild -sdk $(SDKROOT) -version Path)
CFLAGS += -isysroot $(SDKPATH) -miphoneos-version-min=$(SDKVERSION)
LIBFLAGS += -isysroot $(SDKPATH) -miphoneos-version-min=$(SDKVERSION)
else
XILogFLAG = -framework XILog
CFLAGS += -mmacosx-version-min=$(SDKVERSION)
LIBFLAGS += -mmacosx-version-min=$(SDKVERSION)
endif

HOSTCC = cc
CC = xcrun -sdk $(SDKROOT) cc

ifdef RC_BUILDIT
DOING_BUILDIT=yes
endif

ifdef RC_OS
DOING_BUILDIT=yes
endif

ifdef DOING_BUILDIT
include $(MAKEFILEPATH)/CoreOS/ReleaseControl/Common.make
MY_ARCH = $(patsubst %, -arch %, $(RC_ARCHS)) 
install:: xnu_quick_test
else
	ifndef SRCROOT
		SRCROOT=$(shell /bin/pwd)
	endif
	ifndef OBJROOT
		OBJROOT=$(SRCROOT)/BUILD/obj
	endif
	ifndef DSTROOT
		DSTROOT=$(SRCROOT)/BUILD/dst
	endif
	
	ifndef ARCH
		ARCH=i386 x86_64
		# this hack should be removed once tconf gets
		# <rdar://problem/6618734>
		ifeq "$(Product)" "iPhone"
		ARCH=armv7
		endif
		ifeq "$(Product)" "AppleTV"
		ARCH=i386
		endif
	endif
	
	ifdef ARCH
		MY_ARCH = $(patsubst %, -arch %, $(ARCH)) # allows building multiple archs.
	endif

	CFLAGS += $(MY_ARCH)
endif


CFLAGS += -g -I $(SDKPATH)/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders/ -F/AppleInternal/Library/Frameworks/ $(MORECFLAGS) -Wno-deprecated-declarations
LIBFLAGS += -I $(SDKPATH)/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders  -F/AppleInternal/Library/Frameworks/ $(XILogFLAG)

# The current implementation of the content protection test requires IOKit.
ifeq "$(Product)" "iPhone"
LIBFLAGS += -framework IOKit
endif

MY_OBJECTS = $(OBJROOT)/main.o $(OBJROOT)/memory_tests.o $(OBJROOT)/misc.o \
			 $(OBJROOT)/sema_tests.o $(OBJROOT)/shared_memory_tests.o \
			 $(OBJROOT)/socket_tests.o $(OBJROOT)/tests.o \
			 $(OBJROOT)/xattr_tests.o $(OBJROOT)/kqueue_tests.o \
			 $(OBJROOT)/machvm_tests.o $(OBJROOT)/commpage_tests.o \
			 $(OBJROOT)/atomic_fifo_queue_test.o $(OBJROOT)/sched_tests.o \
			 $(OBJROOT)/pipes_tests.o

ifneq "$(Product)" "iPhone"
MY_OBJECTS += $(OBJROOT)/32bit_inode_tests.o
else
MY_OBJECTS += $(OBJROOT)/content_protection_test.o
endif

# In networked home directories, the chown will fail; we notice and print a helpful message
CHOWN_COMMAND=sudo chown root $(DSTROOT)/xnu_quick_test
PERM_ADVICE="\tYou'll have to set the executable's permissions yourself: chown to root and chmod to 4755. You may need to move to a local volume to do that."
xnu_quick_test : $(OBJROOT) $(DSTROOT) $(MY_OBJECTS) helpers
	sudo rm -rf $(DSTROOT)/xnu_quick_test
	$(CC) $(MY_ARCH) $(LIBFLAGS) -o $(DSTROOT)/xnu_quick_test $(MY_OBJECTS)
	@echo $(CHOWN_COMMAND) # Hack so we don't echo help-message echo
	@$(CHOWN_COMMAND) || echo $(PERM_ADVICE)
	sudo chmod 4755 $(DSTROOT)/xnu_quick_test

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
helpers : helpers/sleep.c helpers/launch.c helpers/arch.c helpers/data_exec.c helperdir $(OBJROOT)/misc.o
ifneq "$(Product)" "iPhone"
	$(CC) -arch i386                              helpers/sleep.c -o $(DSTROOT)/helpers/sleep-i386
endif
ifeq "$(Product)" "MacOSX"
	$(CC) -arch x86_64 -pagezero_size 0x100000000 helpers/sleep.c -o $(DSTROOT)/helpers/sleep-x86_64-4G
	$(CC) -arch x86_64 -pagezero_size 0x1000      helpers/sleep.c -o $(DSTROOT)/helpers/sleep-x86_64-4K
endif
ifneq "$(Product)" "iPhone"
	$(CC) $(LIBFLAGS) -arch i386	$(OBJROOT)/misc.o helpers/launch.c -o $(DSTROOT)/helpers/launch-i386
endif
ifeq "$(Product)" "MacOSX"
	$(CC) $(LIBFLAGS) -arch x86_64	$(OBJROOT)/misc.o helpers/launch.c -o $(DSTROOT)/helpers/launch-x86_64
	$(CC) $(MY_ARCH) 	helpers/arch.c -o $(DSTROOT)/helpers/arch
	$(CC) $(MY_ARCH) 	helpers/data_exec.c -o $(DSTROOT)/helpers/data_exec
	$(CC) -arch i386 	-DNXDATA32TESTNONX helpers/data_exec.c -o $(DSTROOT)/helpers/data_exec32nonxspawn

endif
ifeq "$(Product)" "iPhone"
	$(CC) $(CFLAGS) helpers/sleep.c -o $(DSTROOT)/helpers/sleep-arm
	$(CC) $(LIBFLAGS) $(CFLAGS) $(OBJROOT)/misc.o helpers/launch.c -o $(DSTROOT)/helpers/launch-arm
	$(CC) $(MY_ARCH) $(CFLAGS) helpers/arch.c -o $(DSTROOT)/helpers/arch
endif
	
	
helperdir :
	mkdir -p $(DSTROOT)/helpers

$(OBJROOT) :
	mkdir -p $(OBJROOT);
	
$(DSTROOT) :
	mkdir -p $(DSTROOT);

$(OBJROOT)/main.o : main.c tests.h
	$(CC) $(CFLAGS) -c main.c  -o $@
	
$(OBJROOT)/memory_tests.o : memory_tests.c tests.h
	$(CC) $(CFLAGS) -c memory_tests.c  -o $@

# misc.o has to be built 3-way for the helpers to link
$(OBJROOT)/misc.o : misc.c tests.h
ifeq "$(Product)" "iPhone"
	$(CC) -arch armv7 $(CFLAGS) -c misc.c   -o $@
else
	$(CC) -arch i386 -arch x86_64 $(CFLAGS) -c misc.c   -o $@
endif
	
$(OBJROOT)/sema_tests.o : sema_tests.c tests.h
	$(CC) $(CFLAGS) -c sema_tests.c   -o $@
	
$(OBJROOT)/shared_memory_tests.o : shared_memory_tests.c tests.h
	$(CC) $(CFLAGS) -c shared_memory_tests.c   -o $@

$(OBJROOT)/socket_tests.o : socket_tests.c tests.h
	$(CC) $(CFLAGS) -c socket_tests.c   -o $@

$(OBJROOT)/tests.o : tests.c tests.h
	$(CC) $(CFLAGS) -c tests.c    -o $@

$(OBJROOT)/xattr_tests.o : xattr_tests.c tests.h
	$(CC) $(CFLAGS) -c xattr_tests.c    -o $@

$(OBJROOT)/machvm_tests.o : machvm_tests.c tests.h
	$(CC) $(CFLAGS) -c machvm_tests.c    -o $@

$(OBJROOT)/sched_tests.o : sched_tests.c tests.h
	$(CC) $(CFLAGS) -c sched_tests.c    -o $@

$(OBJROOT)/kqueue_tests.o : kqueue_tests.c tests.h
	$(CC) $(CFLAGS) -c kqueue_tests.c   -o $@

$(OBJROOT)/32bit_inode_tests.o : 32bit_inode_tests.c tests.h
	$(CC) $(CFLAGS) -c 32bit_inode_tests.c    -o $@

$(OBJROOT)/commpage_tests.o : commpage_tests.c tests.h
	$(CC) $(CFLAGS) -c commpage_tests.c    -o $@
	
$(OBJROOT)/atomic_fifo_queue_test.o : atomic_fifo_queue_test.c tests.h
	$(CC) $(CFLAGS) -c atomic_fifo_queue_test.c    -o $@

$(OBJROOT)/content_protection_test.o : content_protection_test.c tests.h
	$(CC) $(CFLAGS) -c content_protection_test.c -o $@

$(OBJROOT)/pipes_tests.o : pipes_tests.c tests.h
	$(CC) $(CFLAGS) -c pipes_tests.c -o $@

ifndef DOING_BUILDIT
.PHONY : clean
clean :
	sudo rm -Rf $(DSTROOT)/xnu_quick_test
	sudo rm -Rf $(DSTROOT)/helpers/*
	rm -Rf $(OBJROOT)/*.o
endif
