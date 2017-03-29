PROJECT := xnu/darwintests

# When building as part of xnu_tests, we get passed a DSTROOT that's got the
# unit test path in it already.  But, BASEDSTROOT doesn't, so use that instead.
ifdef BASEDSTROOT
override DSTROOT = $(BASEDSTROOT)
endif

DEVELOPER_DIR ?= /Applications/Xcode.app/Contents/Developer/

# the xnu build system will only ever call us with the default target
.DEFAULT_GOAL := install

include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.common

OTHER_CFLAGS  = -Weverything -Wno-gnu-union-cast -Wno-missing-field-initializers -Wno-partial-availability
OTHER_CFLAGS += -Wno-missing-noreturn -Wno-vla -Wno-reserved-id-macro -Wno-documentation-unknown-command
OTHER_CFLAGS += -Wno-padded -Wno-used-but-marked-unused -Wno-covered-switch-default
OTHER_CFLAGS += --std=gnu11 -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
OTHER_CFLAGS += -DT_NAMESPACE=xnu

CODESIGN:=$(shell xcrun -sdk "$(TARGETSDK)" -find codesign)
CODESIGN_ALLOCATE:=$(shell xcrun -sdk "$(TARGETSDK)" -find codesign_allocate)

# to have custom compiler flags to
# target: OTHER_CFLAGS += <my flags>

backtracing: OTHER_CFLAGS += -F $(SDKROOT)/System/Library/PrivateFrameworks
backtracing: OTHER_LDFLAGS += -framework CoreSymbolication

data_protection: OTHER_LDFLAGS += -framework IOKit

kdebug: INVALID_ARCHS = i386
kdebug: OTHER_LDFLAGS = -lktrace

EXCLUDED_SOURCES += kperf_helpers.c

ifeq ($(PLATFORM),iPhoneOS)
CONFIG_FREEZE_DEFINE:= -DCONFIG_FREEZE
else
CONFIG_FREEZE_DEFINE:=
EXCLUDED_SOURCES += jumbo_va_spaces_28530648.c
endif

perf_compressor: OTHER_CFLAGS += $(CONFIG_FREEZE_DEFINE)

kperf: INVALID_ARCHS = i386
kperf: OTHER_CFLAGS += kperf_helpers.c
kperf: OTHER_CFLAGS += -F $(SDKROOT)/System/Library/PrivateFrameworks
kperf: OTHER_LDFLAGS += -framework kperf -framework kperfdata -lktrace

kperf_backtracing: INVALID_ARCHS = i386
kperf_backtracing: OTHER_CFLAGS += kperf_helpers.c
kperf_backtracing: OTHER_CFLAGS += -F $(SDKROOT)/System/Library/PrivateFrameworks
kperf_backtracing: OTHER_LDFLAGS += -framework kperf -framework kperfdata -lktrace
kperf_backtracing: OTHER_LDFLAGS += -framework CoreSymbolication

mach_get_times: OTHER_LDFLAGS += -ldarwintest_utils

perf_exit: OTHER_LDFLAGS = -lktrace
perf_exit: INVALID_ARCHS = i386

task_inspect: CODE_SIGN_ENTITLEMENTS = task_inspect.entitlements
task_inspect: OTHER_CFLAGS += -DENTITLED=1

CUSTOM_TARGETS += perf_exit_proc

perf_exit_proc:
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) perf_exit_proc.c -o $(SYMROOT)/perf_exit_proc

install-perf_exit_proc: perf_exit_proc
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/perf_exit_proc $(INSTALLDIR)/

perf_kdebug: INVALID_ARCHS = i386

stackshot_idle_25570396: INVALID_ARCHS = i386
stackshot_idle_25570396: OTHER_LDFLAGS += -lkdd -framework Foundation

stackshot_block_owner_14362384: INVALID_ARCHS = i386
stackshot_block_owner_14362384: OTHER_LDFLAGS += -framework Foundation -lpthread -lkdd

ifeq ($(PLATFORM),iPhoneOS)
OTHER_TEST_TARGETS += jumbo_va_spaces_28530648_unentitled
jumbo_va_spaces_28530648: CODE_SIGN_ENTITLEMENTS = jumbo_va_spaces_28530648.entitlements
jumbo_va_spaces_28530648: OTHER_CFLAGS += -DENTITLED=1
jumbo_va_spaces_28530648: OTHER_LDFLAGS += -ldarwintest_utils

jumbo_va_spaces_28530648_unentitled: OTHER_LDFLAGS += -ldarwintest_utils
jumbo_va_spaces_28530648_unentitled: jumbo_va_spaces_28530648.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
endif

include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.targets
