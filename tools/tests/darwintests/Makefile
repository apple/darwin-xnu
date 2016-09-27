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
OTHER_CFLAGS += -Wno-padded -Wno-used-but-marked-unused
OTHER_CFLAGS += --std=gnu11 -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders

# to have custom compiler flags to
# target: OTHER_CFLAGS += <my flags>

backtracing: OTHER_CFLAGS += -F $(SDKROOT)/System/Library/PrivateFrameworks
backtracing: OTHER_LDFLAGS += -framework CoreSymbolication

kdebug: INVALID_ARCHS = i386
kdebug: OTHER_LDFLAGS = -lktrace

EXCLUDED_SOURCES += kperf_helpers.c

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

stackshot_idle_25570396: INVALID_ARCHS = i386
stackshot_idle_25570396: OTHER_LDFLAGS += -lkdd -framework Foundation

include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.targets
