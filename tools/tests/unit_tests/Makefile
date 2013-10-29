#!/usr/bin/make
# This file lists all individual tests added over time to test various functionality.
# The Raft TestBot framework runs the tests based on the targets listed in this file.
# Please review the following guidelines to ensure successful execution of your test case
#
# == Steps followed by Raft testbot ==
# * find target name from this Makefile. A target is identified by the string <targetname>: related files
# * build the target with the command "make <targetname>". The current dir is same as of this Makefile
# * The test is executed with following commands "cd BUILD/dst/; ./<targetname> "
# * The exit value of <targetname> is logged. (0 = PASS and <any integer> = FAIL) 
# * remove the BUILD directory
#
# == Note about SDKROOT ==
# The environment variable SDKROOT must be passed to select the appropriate SDK.
# x86/OSX is the default, so to build for iphone, you must:
#
# 64-bit:  $make SDKROOT=iphoneos.internal <targetname>
# 32-bit:  $make SDKROOT=iphoneos.internal ARCH_CONFIGS="armv7" <targetname>
#
# == How to add a new test ==
# * Create a test directory based on radar #. (for example test_<number>)
# * Put test specific files in the directory. 
# * Add an entry in this Makefile (reserved targetnames are {run_tests.sh, xnu_target_executables.list, build_*.log})
#    targetname: testdir/programname.c
#        <provide your compile command with output in $(BUILDDIR)>
#
# * Check if your target name is listed in the right configurations.
#   $make list_targets 
#   optionally you can pass SDKROOT=iphoneos|iphoneos.internal|macosx|macosx.internal and verify
#   the built binary is of right arch and config.
#
# * verify that your test setup works by running the following commands
#   $make <targetname> 
#   $cd BUILD/dst/
#   $./targetname
#
# == Easy Option ==
# look at some example targets in this file and replicate that :)
#

ifneq ($(SRCROOT),)
SRCDIR=$(SRCROOT)
else
SRCDIR?=$(shell /bin/pwd)
endif

ifneq ($(DSTROOT),)
BUILDDIR?=$(DSTROOT)
else
BUILDDIR?=$(SRCDIR)/BUILD/dst
endif

# make sure we have a build directory
$(shell [ -d "$(BUILDDIR)" ] || mkdir -p $(BUILDDIR))

SDKROOT ?= /
TARGETSDK:=$(SDKROOT)


# setup the TARGETSDK and SDKROOT variables
ifeq (/,$(SDKROOT))
SDKROOTPATH=/
else
SDKROOTPATH:=$(shell /usr/bin/xcodebuild -sdk $(TARGETSDK) -version Path)
endif

ifeq ($(SDKROOTPATH),)
$(error "Unable to find any SDKROOT on host. Exiting")
endif

PRIVATE_INCLUDES = $(SDKROOTPATH)/System/Library/Frameworks/System.framework/PrivateHeaders

#arch configs if not provided
ifdef RC_ARCHS
ARCH_CONFIGS:=$(RC_ARCHS)
endif
ifeq ($(ARCH_CONFIGS),)
ARCH_CONFIGS:=
ifeq (iPhone,$(findstring iPhone,$(SDKROOTPATH)))
ARCH_CONFIGS:=-arch armv7
endif

else
TMP_ARCHCONF:=$(foreach argarch,$(ARCH_CONFIGS),-arch $(argarch) )
override ARCH_CONFIGS:=$(TMP_ARCHCONF)
endif


#setup the compiler flags.
ifeq (iPhone,$(findstring iPhone,$(SDKROOTPATH)))
CFLAGS=-I$(BUILDDIR) -I. -isysroot $(SDKROOTPATH) $(ARCH_CONFIGS)
CC=xcrun -sdk $(TARGETSDK) clang 
MIG=xcrun -sdk $(TARGETSDK) mig
XCODEBUILD=xcodebuild -sdk iphoneos.internal $(ARCH_CONFIGS)
CODESIGN=$(shell xcrun -sdk $(TARGETSDK) -find codesign)
CODESIGN_ALLOCATE=$(shell xcrun -sdk $(TARGETSDK) -find codesign_allocate)
TARGET_NAME=ios
else
#Compiler flags for macosx
CFLAGS=-I$(BUILDDIR) -I. $(ARCH_CONFIGS)
CC=clang
MIG=xcrun mig
XCODEBUILD=xcodebuild
CODESIGN=codesign
CODESIGN_ALLOCATE=$(shell xcrun -find codesign_allocate)
TARGET_NAME=osx
endif

#Flags that define the environment
TARGETOSVERS:=$(shell /usr/bin/xcodebuild -sdk $(TARGETSDK) -version ProductVersion)
TARGETOSBUILDVERS:=$(shell /usr/bin/xcodebuild -sdk $(TARGETSDK) -version ProductBuildVersion)
SDKTARGET_STR:=$(subst .,_,$(TARGETSDK))
MORECFLAGS=-D TARGET_SDK_$(SDKTARGET_STR)=1 -D TARGET_OS_VERS=\"$(TARGETOSVERS)\" -D TARGET_OS_BUILD_VERS=\"$(TARGETOSBUILDVERS)\"

#special recipe for special targets: list_targets and clean
define _sed_target_extract_script
/^$$/ { n 
/^[^ ]*:/p 
}
endef
export sed_target_extract_script=$(_sed_target_extract_script)
all:
	@ for TARGET in `make list_targets`; do \
	  if [ $$TARGET != all ]; then \
	    make $$TARGET DSTROOT="$(BUILDDIR)/$$TARGET"; \
	  fi \
	done
list_targets:
	@ make -rpn | sed  -n -e "$$sed_target_extract_script" | cut -d':' -f1 | grep -v '^clean' | grep -v '^list_targets' 

clean:
	rm -fr ./BUILD/
# == List of targets for test cases ==
#Note: target name should be same as the executable in $(BUILDDIR) 
#And: target name has to be seperate from source directory name. Using "_src" suffix is a good idea.
sampletest: sampletest.c
	$(CC) -o $(BUILDDIR)/$@ $^ $(CFLAGS) $(MORECFLAGS)

pipe_test_10807398: pipe_test_10807398_src/parent.c pipe_test_10807398_src/child.c
	$(CC) -o $(BUILDDIR)/$@   pipe_test_10807398_src/parent.c $(CFLAGS)
	$(CC) -o $(BUILDDIR)/child  pipe_test_10807398_src/child.c $(CFLAGS)

pipes_fill_procinfo_11179336: pipes_fill_procinfo_11179336.c
	$(CC) -o $(BUILDDIR)/$@ pipes_fill_procinfo_11179336.c $(CFLAGS)

test_wq_exit_race_panic_10970548: test_wq_exit_race_panic_10970548.c
	$(CC) -o $(BUILDDIR)/$@ test_wq_exit_race_panic_10970548.c $(CFLAGS)

ptrace_tests_10767133: ptrace_tests_10767133_src/ptrace_tests_10767133.c 
	$(CC) -O0 -o $(BUILDDIR)/ptrace_tests_10767133  ptrace_tests_10767133_src/ptrace_tests_10767133.c $(CFLAGS) -Wall

ptrace_test_12507045: ptrace_test_12507045_src/ptrace_test.c
	$(CC) -O0 -o $(BUILDDIR)/ptrace_test_12507045 $< $(CFLAGS)

clock_types_6368156: clock_types_6368156.c
	$(CC) -o $(BUILDDIR)/$@ $^ $(CFLAGS)

semctl_test_8534495: semctl_test_8534495_src/semctl_test_8534495.c
	$(CC) -o $(BUILDDIR)/semctl_test_8534495 semctl_test_8534495_src/semctl_test_8534495.c  $(CFLAGS)

ptcwd_test_11269991: ptcwd_test_11269991_src/ptcwd_test_11269991.c
	$(CC) -o $(BUILDDIR)/ptcwd_test_11269991 ptcwd_test_11269991_src/ptcwd_test_11269991.c $(CFLAGS)

sprace_test_11891562: sprace_test_11891562_src/sprace_test_11891562.c
	$(CC) -o $(BUILDDIR)/sprace_test_11891562 sprace_test_11891562_src/sprace_test_11891562.c $(CFLAGS)

guarded_fd_tests_11746236: guarded_fd_tests_11746236_src/mach_exc.defs guarded_fd_tests_11746236_src/guarded_test_framework.c guarded_fd_tests_11746236_src/guarded_test.c
	$(MIG) $(CFLAGS) \
		-user $(BUILDDIR)/mach_excUser.c \
		-server $(BUILDDIR)/mach_excServer.c \
		-header $(BUILDDIR)/mach_exc.h \
		guarded_fd_tests_11746236_src/mach_exc.defs
	$(CC) -o $(BUILDDIR)/guarded_fd_tests_11746236 \
		guarded_fd_tests_11746236_src/guarded_test_framework.c \
		$(BUILDDIR)/mach_excServer.c $(CFLAGS) -I$(PRIVATE_INCLUDES) -I$(BUILDDIR)
	$(CC) -o $(BUILDDIR)/guarded_test \
		guarded_fd_tests_11746236_src/guarded_test.c \
		-I$(PRIVATE_INCLUDES) $(CFLAGS)

thread_get_state_11918811: thread_get_state_11918811_src/thread_get_state.c
	$(MIG) $(CFLAGS) \
		-sheader $(BUILDDIR)/excserver.h \
		-server $(BUILDDIR)/excserver.c \
		-header /dev/null -user /dev/null \
		thread_get_state_11918811_src/excserver.defs
	$(CC) -o $(BUILDDIR)/thread_get_state_11918811 \
		thread_get_state_11918811_src/thread_get_state.c \
		$(BUILDDIR)/excserver.c \
		$(CFLAGS)

fcntlrangecheck_tests_11202484: fcntlrangecheck_tests_11202484_src/fcntlrangecheck_tests_11202484.c
	$(CC) -o $(BUILDDIR)/fcntlrangecheck_tests_11202484 fcntlrangecheck_tests_11202484_src/fcntlrangecheck_tests_11202484.c $(CFLAGS)

test_waitqlocktry_12053360: test_waitqlocktry_12053360.c
	$(CC) -o $(BUILDDIR)/test_waitqlocktry_12053360 test_waitqlocktry_12053360.c $(CFLAGS)

guarded_mach_port_tests_11178535: guarded_mach_port_tests_11178535_src/mach_exc.defs guarded_mach_port_tests_11178535_src/guarded_test_framework.c guarded_mach_port_tests_11178535_src/guarded_test.c
	$(MIG) $(CFLAGS) \
		-user $(BUILDDIR)/mach_excUser.c \
		-server $(BUILDDIR)/mach_excServer.c \
		-header $(BUILDDIR)/mach_exc.h \
		guarded_mach_port_tests_11178535_src/mach_exc.defs
	$(CC) -o $(BUILDDIR)/guarded_mach_port_tests_11178535 \
		guarded_mach_port_tests_11178535_src/guarded_test_framework.c \
		$(BUILDDIR)/mach_excServer.c $(CFLAGS) -I$(PRIVATE_INCLUDES) -I$(BUILDDIR)
	$(CC) -o $(BUILDDIR)/guarded_mp_test \
		guarded_mach_port_tests_11178535_src/guarded_test.c \
		-I$(PRIVATE_INCLUDES) $(CFLAGS)

cpu_monitor_tests_11646922: cpu_monitor_tests_11646922_src/cpumon_test_framework.c
	$(MIG) $(CFLAGS) \
		-sheader $(BUILDDIR)/excserver.h \
		-server $(BUILDDIR)/excserver.c \
		-header /dev/null -user /dev/null \
		cpu_monitor_tests_11646922_src/mach_exc.defs
	$(CC) -o $(BUILDDIR)/cpu_monitor_tests_11646922 \
		cpu_monitor_tests_11646922_src/cpumon_test_framework.c \
		$(BUILDDIR)/excserver.c \
		$(CFLAGS) $(MORECFLAGS) -I$(PRIVATE_INCLUDES)
	$(XCODEBUILD) -project cpu_monitor_tests_11646922_src/cpu_hog/cpu_hog.xcodeproj TARGET_BUILD_DIR=$(BUILDDIR)
	$(CC) -o $(BUILDDIR)/mem_hog \
		cpu_monitor_tests_11646922_src/mem_hog/mem_hog.c \
		$(CFLAGS) $(MORECFLAGS) -I$(PRIVATE_INCLUDES)

monitor_stress_12901965: monitor_stress_12901965_src/monitor_stress/monitor_stress.m
	echo '#!/bin/sh\n./monitor_stress -e 20\n./monitor_stress -w 3 -e 20' > $(BUILDDIR)/monitor_stress_12901965
	chmod +x $(BUILDDIR)/monitor_stress_12901965
	$(XCODEBUILD) -target $(TARGET_NAME) -project monitor_stress_12901965_src/monitor_stress.xcodeproj TARGET_BUILD_DIR=$(BUILDDIR)

codesigntests: codesigntests.c codesigntests-entitlements.plist
	$(CC) -o $(BUILDDIR)/codesigntests codesigntests.c $(CFLAGS)
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) \
	    $(CODESIGN) -s - --entitlements codesigntests-entitlements.plist $(BUILDDIR)/codesigntests

libproc_privilege_test_13203438: libproc_privilege_test_13203438_src/libproc_privilege_test_13203438.c
	$(CC) -o $(BUILDDIR)/libproc_privilege_test_13203438 libproc_privilege_test_13203438_src/libproc_privilege_test_13203438.c $(CFLAGS)

