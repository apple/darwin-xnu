PROJECT := xnu/darwintests

# When building as part of xnu_tests, we get passed a DSTROOT that's got the
# unit test path in it already.  But, BASEDSTROOT doesn't, so use that instead.
ifdef BASEDSTROOT
override DSTROOT = $(BASEDSTROOT)
endif

ENABLE_LTE_TESTS=YES

OTHER_LTE_INCLUDE_FILES += \
	/System/Library/PrivateFrameworks/LoggingSupport.framework, \
	/System/Library/PrivateFrameworks/MobileKeyBag.framework, \
	/System/Library/Frameworks/IOSurface.framework, \
	/usr/local/lib/libdarwintest_utils.dylib, \
	/usr/lib/libapple_crypto.dylib,

DEVELOPER_DIR ?= $(shell xcode-select -p)

# the xnu build system will only ever call us with the default target
.DEFAULT_GOAL := install

include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.common

OTHER_CFLAGS  = -Weverything -Wno-gnu-union-cast -Wno-missing-field-initializers -Wno-partial-availability
OTHER_CFLAGS += -Wno-missing-noreturn -Wno-vla -Wno-reserved-id-macro -Wno-documentation-unknown-command
OTHER_CFLAGS += -Wno-padded -Wno-used-but-marked-unused -Wno-covered-switch-default -Wno-nullability-extension
OTHER_CFLAGS += -Wno-gnu-empty-initializer -Wno-unused-macros -Wno-undef -Wno-fixed-enum-extension
OTHER_CFLAGS += --std=gnu11 -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
OTHER_CFLAGS += -UT_NAMESPACE_PREFIX -DT_NAMESPACE_PREFIX=xnu
OTHER_CFLAGS += -F $(SDKROOT)/System/Library/PrivateFrameworks

CODESIGN:=$(shell xcrun -sdk "$(TARGETSDK)" -find codesign)
CODESIGN_ALLOCATE:=$(shell xcrun -sdk "$(TARGETSDK)" -find codesign_allocate)

# to have custom compiler flags to
# target: OTHER_CFLAGS += <my flags>

atm_diagnostic_flag: OTHER_CFLAGS += drop_priv.c

atm_diagnostic_flag_entitled: CODE_SIGN_ENTITLEMENTS = atm_diagnostic_flag.entitlements
atm_diagnostic_flag_entitled: OTHER_CFLAGS += drop_priv.c

testposixshm: INVALID_ARCHS = i386

avx: INVALID_ARCHS = i386
avx: OTHER_CFLAGS += -mavx512f -mavx512bw -mavx512vl
avx: OTHER_CFLAGS += -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
avx: CONFIG_FLAGS := $(filter-out -O%,$(CONFIG_FLAGS))
# Level 2 optimization must be used to prevent compiler from generating
# invalid instructions when compiling with AVX-512 flags.
avx: CONFIG_FLAGS += -O2
# Disable vzeroupper insertion to work around rdar://problem/35035096
avx: CONFIG_FLAGS += -mllvm -x86-use-vzeroupper=0
ifneq (osx,$(TARGET_NAME))
EXCLUDED_SOURCES += avx.c
endif

backtracing: OTHER_LDFLAGS += -framework CoreSymbolication

data_protection: OTHER_LDFLAGS += -ldarwintest_utils -framework IOKit

immovable_send: excserver
immovable_send: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)
immovable_send: OTHER_LDFLAGS += -ldarwintest_utils -lpthread -framework IOKit

CUSTOM_TARGETS += immovable_send_client
immovable_send: immovable_send_client

immovable_send_client: immovable_send_client.c
	$(CC) $(DT_CFLAGS) -I $(OBJROOT) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) immovable_send_client.c -o $(SYMROOT)/immovable_send_client

install-immovable_send_client: immovable_send_client
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/immovable_send_client $(INSTALLDIR)/

kdebug: INVALID_ARCHS = i386
kdebug: OTHER_LDFLAGS = -framework ktrace -ldarwintest_utils -framework kperf

EXCLUDED_SOURCES += drop_priv.c kperf_helpers.c xnu_quick_test_helpers.c memorystatus_assertion_helpers.c bpflib.c in_cksum.c

ifneq ($(PLATFORM),iPhoneOS)
EXCLUDED_SOURCES += jumbo_va_spaces_28530648.c perf_compressor.c memorystatus_freeze_test.c
endif

perf_compressor: OTHER_LDFLAGS += -ldarwintest_utils
perf_compressor: CODE_SIGN_ENTITLEMENTS=./private_entitlement.plist

memorystatus_freeze_test: CODE_SIGN_ENTITLEMENTS=./task_for_pid_entitlement.plist
memorystatus_freeze_test: OTHER_LDFLAGS += -ldarwintest_utils
memorystatus_freeze_test: OTHER_CFLAGS += -ldarwintest_utils memorystatus_assertion_helpers.c

memorystatus_is_assertion: OTHER_LDFLAGS += -ldarwintest_utils
memorystatus_is_assertion: OTHER_CFLAGS += memorystatus_assertion_helpers.c

shared_cache_tests: INVALID_ARCHS = i386
shared_cache_tests: OTHER_LDFLAGS += -ldarwintest_utils

stackshot_tests: OTHER_CFLAGS += -Wno-objc-messaging-id
stackshot_tests: OTHER_LDFLAGS += -lkdd -ldarwintest_utils -framework Foundation
stackshot_tests: INVALID_ARCHS = i386

stackshot_accuracy: OTHER_CFLAGS += -ldarwintest_utils -Wno-objc-messaging-id
stackshot_accuracy: OTHER_LDFLAGS += -lkdd -ldarwintest_utils -framework Foundation
stackshot_accuracy: INVALID_ARCHS = i386

telemetry: OTHER_LDFLAGS = -framework ktrace -framework CoreFoundation
telemetry: INVALID_ARCHS = i386

memorystatus_zone_test: INVALID_ARCHS = i386
memorystatus_zone_test: OTHER_CFLAGS += -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
memorystatus_zone_test: OTHER_LDFLAGS += -framework ktrace
memorystatus_zone_test: OTHER_LDFLAGS += -ldarwintest_utils

kpc: OTHER_LDFLAGS += -framework kperf -framework ktrace
kpc: INVALID_ARCHS = i386

kperf: INVALID_ARCHS = i386
kperf: OTHER_CFLAGS += kperf_helpers.c
kperf: OTHER_LDFLAGS += -framework kperf -framework kperfdata -framework ktrace -ldarwintest_utils

kperf_backtracing: INVALID_ARCHS = i386
kperf_backtracing: OTHER_CFLAGS += kperf_helpers.c
kperf_backtracing: OTHER_LDFLAGS += -framework kperf -framework kperfdata -framework ktrace
kperf_backtracing: OTHER_LDFLAGS += -framework CoreSymbolication

kevent_qos: OTHER_CFLAGS += -Wno-unused-macros
kevent_qos: OTHER_CFLAGS += -I $(OBJROOT)/

mach_get_times: OTHER_LDFLAGS += -ldarwintest_utils

monotonic_core: OTHER_LDFLAGS += -framework ktrace
monotonic_core: INVALID_ARCHS = i386

perf_exit: perf_exit_proc
perf_exit: OTHER_LDFLAGS = -framework ktrace -ldarwintest_utils
perf_exit: INVALID_ARCHS = i386
perf_exit: CODE_SIGN_ENTITLEMENTS=./private_entitlement.plist

CUSTOM_TARGETS += prioritize_process_launch_helper
prioritize_process_launch: prioritize_process_launch_helper

prioritize_process_launch_helper: prioritize_process_launch_helper.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) prioritize_process_launch_helper.c -o $(SYMROOT)/prioritize_process_launch_helper
	echo $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@; \
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-prioritize_process_launch_helper: prioritize_process_launch_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/prioritize_process_launch_helper $(INSTALLDIR)/


perf_spawn_fork: CODE_SIGN_ENTITLEMENTS=./private_entitlement.plist

mach_exception_reply: OTHER_CFLAGS += -Wno-cast-align

os_thread_self_restrict: os_thread_self_restrict.c os_thread_self_restrict-entitlements.plist
os_thread_self_restrict: CODE_SIGN_ENTITLEMENTS=os_thread_self_restrict-entitlements.plist

osptr: OTHER_CXXFLAGS += -I$(SRCROOT)/../libkern -std=c++98
osptr: OTHER_CXXFLAGS += osptr_helper.cpp

osptr_dumb: OTHER_CXXFLAGS += -I$(SRCROOT)/../libkern -std=c++17

osptr_11: OTHER_CXXFLAGS += -I$(SRCROOT)/../libkern -std=c++11
osptr_11: OTHER_CXXFLAGS += osptr_helper.cpp
osptr_11: osptr.cpp
	$(CXX) $(DT_CXXFLAGS) $(OTHER_CXXFLAGS) $(CXXFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

osptr_17: OTHER_CXXFLAGS += -I$(SRCROOT)/../libkern -std=c++17
osptr_17: OTHER_CXXFLAGS += osptr_helper.cpp
osptr_17: osptr.cpp
	$(CXX) $(DT_CXXFLAGS) $(OTHER_CXXFLAGS) $(CXXFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

EXCLUDED_SOURCES += osptr_helper.cpp

os_refcnt: OTHER_CFLAGS += -I$(SRCROOT)/../libkern/ -Wno-gcc-compat -Wno-undef -O3 -flto

task_inspect: CODE_SIGN_ENTITLEMENTS = task_inspect.entitlements
task_inspect: OTHER_CFLAGS += -DENTITLED=1

turnstile_multihop: OTHER_CFLAGS += -Wno-unused-macros
turnstile_multihop: OTHER_CFLAGS += -I $(OBJROOT)/

CUSTOM_TARGETS += perf_exit_proc

perf_exit_proc:
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) perf_exit_proc.c -o $(SYMROOT)/perf_exit_proc

install-perf_exit_proc: perf_exit_proc
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/perf_exit_proc $(INSTALLDIR)/

stackshot_idle_25570396: INVALID_ARCHS = i386
stackshot_idle_25570396: OTHER_LDFLAGS += -lkdd -framework Foundation

stackshot_block_owner_14362384: INVALID_ARCHS = i386
stackshot_block_owner_14362384: OTHER_LDFLAGS += -framework Foundation -lpthread -lkdd
ifeq ($(PLATFORM),MacOSX)
stackshot_block_owner_14362384: OTHER_LDFLAGS += -lpcre
endif

all: $(DSTROOT)/usr/local/bin/kcdata

$(DSTROOT)/usr/local/bin/kcdata: $(SRCROOT)/../tools/lldbmacros/kcdata.py
	mkdir -p $(dir $@)
	cp $< $@
	chmod a+x $@

xnu_quick_test: OTHER_CFLAGS += xnu_quick_test_helpers.c

xnu_quick_test_entitled: CODE_SIGN_ENTITLEMENTS = xnu_quick_test.entitlements

CUSTOM_TARGETS += vm_set_max_addr_helper

vm_set_max_addr_helper: vm_set_max_addr_helper.c
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) vm_set_max_addr_helper.c -o $(SYMROOT)/vm_set_max_addr_helper; \
	echo $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@; \
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-vm_set_max_addr_helper: vm_set_max_addr_helper
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/vm_set_max_addr_helper $(INSTALLDIR)/

ifeq ($(PLATFORM),iPhoneOS)
OTHER_TEST_TARGETS += jumbo_va_spaces_28530648_unentitled vm_phys_footprint_legacy
jumbo_va_spaces_28530648: CODE_SIGN_ENTITLEMENTS = jumbo_va_spaces_28530648.entitlements
jumbo_va_spaces_28530648: OTHER_CFLAGS += -DENTITLED=1
jumbo_va_spaces_28530648: OTHER_LDFLAGS += -ldarwintest_utils

jumbo_va_spaces_28530648_unentitled: OTHER_LDFLAGS += -ldarwintest_utils
jumbo_va_spaces_28530648_unentitled: jumbo_va_spaces_28530648.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

vm_phys_footprint_legacy: OTHER_LDFLAGS += -framework CoreFoundation -framework IOSurface
vm_phys_footprint_legacy: OTHER_CFLAGS += -DLEGACY_FOOTPRINT_ENTITLED=1
vm_phys_footprint_legacy: CODE_SIGN_ENTITLEMENTS=./legacy_footprint.entitlement
vm_phys_footprint_legacy: vm_phys_footprint.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

endif

task_info_28439149: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist

proc_info: CODE_SIGN_ENTITLEMENTS = ./task_for_pid_entitlement.plist
proc_info: OTHER_LDFLAGS += -ldarwintest_utils

proc_info_list_kthreads: CODE_SIGN_ENTITLEMENTS = ./proc_info_list_kthreads.entitlements

proc_info_44873309: CODE_SIGN_ENTITLEMENTS = ./proc_info_44873309.entitlements

disk_mount_conditioner: disk_mount_conditioner*
disk_mount_conditioner: CODE_SIGN_ENTITLEMENTS=./disk_mount_conditioner-entitlements.plist
disk_mount_conditioner: OTHER_LDFLAGS += -ldarwintest_utils

disk_mount_conditioner: OTHER_TEST_TARGETS += disk_mount_conditioner_unentitled
disk_mount_conditioner_unentitled: OTHER_CFLAGS += -DTEST_UNENTITLED
disk_mount_conditioner_unentitled: OTHER_LDFLAGS += -ldarwintest_utils
disk_mount_conditioner_unentitled: disk_mount_conditioner.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

work_interval_test: CODE_SIGN_ENTITLEMENTS = work_interval_test.entitlements
work_interval_test: OTHER_CFLAGS += -DENTITLED=1

settimeofday_29193041: OTHER_CFLAGS += drop_priv.c

settimeofday_29193041_entitled: CODE_SIGN_ENTITLEMENTS = settimeofday_29193041.entitlements
settimeofday_29193041_entitled: OTHER_CFLAGS += drop_priv.c

thread_group_set_32261625: OTHER_LDFLAGS = -framework ktrace
thread_group_set_32261625: INVALID_ARCHS = i386

task_info: CODE_SIGN_ENTITLEMENTS = task_for_pid_entitlement.plist

task_vm_info_decompressions: INVALID_ARCHS = x86_64 i386

socket_bind_35243417: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist
socket_bind_35685803: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

net_tuntests: CODE_SIGN_ENTITLEMENTS = network_entitlements.plist

net_bridge: OTHER_CFLAGS += bpflib.c in_cksum.c
net_bridge: OTHER_LDFLAGS += -ldarwintest_utils

ifneq (osx,$(TARGET_NAME))
EXCLUDED_SOURCES += no32exec_35914211.c no32exec_35914211_helper.c
else  # target = osx
CUSTOM_TARGETS += no32exec_35914211_helper no32exec_35914211_helper_binprefs

no32exec_35914211_helper: INVALID_ARCHS = x86_64 i386
no32exec_35914211_helper:
	$(CC) $(LDFLAGS) $(CFLAGS) -arch i386  no32exec_35914211_helper.c -o $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-no32exec_35914211_helper:
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/no32exec_35914211_helper $(INSTALLDIR)/

no32exec_35914211_helper_binprefs: INVALID_ARCHS = x86_64 i386
no32exec_35914211_helper_binprefs:
	$(CC) $(OTHER_CFLAGS) $(CFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) -arch i386 -arch x86_64  no32exec_35914211_helper.c -o $(SYMROOT)/$@;
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

install-no32exec_35914211_helper_binprefs:
	mkdir -p $(INSTALLDIR)
	cp $(SYMROOT)/no32exec_35914211_helper_binprefs $(INSTALLDIR)/

no32exec_35914211: INVALID_ARCHS = i386
no32exec_35914211: no32exec_35914211_helper
no32exec_35914211: no32exec_35914211_helper_binprefs
endif  # (osx,$(TARGET_NAME)))

MIG:=SDKROOT=$(SDKROOT) $(shell xcrun -sdk "$(TARGETSDK)" -find mig)

CUSTOM_TARGETS += excserver

excserver:
	$(MIG) $(CFLAGS) \
		-sheader $(OBJROOT)/excserver.h \
		-server $(OBJROOT)/excserver.c \
		-header /dev/null -user /dev/null \
		excserver.defs
install-excserver: ;

exc_resource_threads: excserver
exc_resource_threads: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)

fp_exception: excserver
fp_exception: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)

ifneq (osx,$(TARGET_NAME))
EXCLUDED_SOURCES += ldt_code32.s ldt.c
else
$(OBJROOT)/ldt_mach_exc_server.c:
	$(MIG) $(CFLAGS) \
		-user /dev/null \
		-server $(OBJROOT)/ldt_mach_exc_server.c \
		-header $(OBJROOT)/ldt_mach_exc.h \
		mach_exc.defs

ldt: INVALID_ARCHS = i386
ldt: $(OBJROOT)/ldt_mach_exc_server.c
ldt: OTHER_CFLAGS += -I $(OBJROOT) $(SRCROOT)/ldt_code32.s -Wl,-pagezero_size,0x1000 -Wno-missing-variable-declarations
ldt: CODE_SIGN_ENTITLEMENTS=ldt_entitlement.plist
endif

ifneq ($(PLATFORM),BridgeOS)
EXCLUDED_SOURCES += remote_time.c
else
remote_time: INVALID_ARCHS = armv7 armv7s arm64_32
endif

vm_phys_footprint: OTHER_LDFLAGS += -framework CoreFoundation -framework IOSurface

debug_control_port_for_pid: CODE_SIGN_ENTITLEMENTS = ./debug_control_port_for_pid_entitlement.plist

prng: OTHER_LDFLAGS += -ldarwintest_utils

OTHER_TEST_TARGETS += io_catalog_send_data

io_catalog_send_data: INVALID_ARCHS = i386
io_catalog_send_data: OTHER_CFLAGS += -DTEST_UNENTITLED -framework IOKit -framework CoreFoundation -framework Foundation
io_catalog_send_data: iokit/io_catalog_send_data.m
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

task_create_suid_cred: CODE_SIGN_ENTITLEMENTS = ./task_create_suid_cred_entitlement.plist

OTHER_TEST_TARGETS += task_create_suid_cred_unentitled
task_create_suid_cred_unentitled: OTHER_CFLAGS += -DUNENTITLED
task_create_suid_cred_unentitled: task_create_suid_cred.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.targets
