PROJECT := xnu/darwintests

ifdef BASEDSTROOT
override DSTROOT = $(BASEDSTROOT)
endif
INVALID_ARCHS = i386
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

SDKROOT ?= driverkit.internal

include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.common

DRIVERKIT_DIR := $(TARGETSDK)/System/DriverKit
DRIVERKIT_TARGET := x86_64-apple-driverkit$(shell xcrun --sdk driverkit.internal --show-sdk-version)

IIG := $(shell xcrun --sdk "$(SDKROOT)" -f iig)

# Enumerate all directories in this folder, excluding the "build" directory
DEXT_SRCS = $(filter-out build,$(shell find . -type d -depth 1 | sed -e "s:./::g"))

# hack: reuse the default CXXFLAGS and LDFLAGS but remove -mmacosx-version-min and -arch. Also adds a few other required flags
# These are used for both iig and clang
DEXT_SHARED_CXXFLAGS := $(filter-out -mmacosx-version-min=%, $(shell echo $(CXXFLAGS) $(OTHER_CXXFLAGS) | sed -e "s/-arch [a-zA-Z0-9_]*//g"))  -isystem$(DRIVERKIT_DIR)/usr/include -iframework$(DRIVERKIT_DIR)/System/Library/Frameworks -std=gnu++14

# These are used just for clang
DEXT_CXXFLAGS := $(DEXT_SHARED_CXXFLAGS) -target $(DRIVERKIT_TARGET)

# These are used just for iig
IIGFLAGS := -- $(DEXT_SHARED_CXXFLAGS) -D__IIG=1 -x c++

# Used just for clang. LDFLAGS are not needed for iig
DEXT_LDFLAGS := $(filter-out -mmacosx-version-min=%, $(shell echo $(LDFLAGS) $(OTHER_LDFLAGS) | sed -e "s/-arch [a-zA-Z0-9_]*//g")) -target $(DRIVERKIT_TARGET) -L$(DRIVERKIT_DIR)/usr/lib -F$(DRIVERKIT_DIR)/System/Library/Frameworks -framework DriverKit


# This generates rules to create dexts from each directory specified in DEXT_SRCS
define GENERATE_DEXT_RULE
## Given the following directory structure:
##   test_driver_123/
##     Info.plist
##     test_driver_123.entitlements
##     [cpp and iig files]
## This produces a dext called com.apple.test_driver_123.dext:
##   com.apple.test_driver_123.dext/
##     com.apple.test_driver_123 [dext executable]
##     Info.plist
##     _CodeSignature/

CUSTOM_TARGETS += com.apple.$1.dext

com.apple.$1.dext : $(patsubst $1/%.cpp,$(OBJROOT)/$1/%.o,$(wildcard $1/*.cpp)) $(patsubst $1/%.iig,$(OBJROOT)/$1/DerivedSources/%.iig.o,$(wildcard $1/*.iig))
	# Create bundle directory
	mkdir -p $(SYMROOT)/$$@
	# Link object files
	$(CXX) $(DEXT_LDFLAGS) $$^ -o $(SYMROOT)/$$@/com.apple.$1
	# Copy Info.plist and sign
	cp $1/Info.plist $(SYMROOT)/$$@
	codesign -vvv --force --sign - --entitlements $1/$1.entitlements --timestamp=none $(SYMROOT)/$$@

install-com.apple.$1.dext: com.apple.$1.dext
	mkdir -p $(INSTALLDIR)
	cp -R $(SYMROOT)/com.apple.$1.dext $(INSTALLDIR)

$(OBJROOT)/$1/DerivedSources/%.iig.o: $(OBJROOT)/$1/DerivedSources/%.iig.cpp
	mkdir -p $(OBJROOT)/$1/DerivedSources
	# Compile *.iig.cpp to object file
	$(CXX) $(DEXT_CXXFLAGS) -I$1/ -I$(OBJROOT)/$1/DerivedSources -c $$^ -o $$@

$(OBJROOT)/$1/DerivedSources/%.iig.cpp: $1/%.iig
	mkdir -p $(OBJROOT)/$1/DerivedSources
	# Generate *.iig.cpp and *.h header files from *.iig
	$(IIG) --def $$^ --impl $$@ --header $$(patsubst %.iig.cpp,%.h,$$@) $(IIGFLAGS)

# Tell make not to delete the intermediate *.iig.cpp file since it is useful for debugging
.PRECIOUS :: $(OBJROOT)/$1/DerivedSources/%.iig.cpp

$(OBJROOT)/$1/%.o: $1/%.cpp $(patsubst $1/%.iig,$(OBJROOT)/$1/DerivedSources/%.iig.o,$(wildcard $1/*.iig))
	# Compile c++ file. The additional dependency is for headers emitted by iig
	$(CXX) $(DEXT_CXXFLAGS) -I$1/ -I$(OBJROOT)/$1/DerivedSources -c $$< -o $$@
endef


ifeq ($(PLATFORM),MacOSX)
$(foreach DEXTSRCDIR,$(DEXT_SRCS),$(eval $(call GENERATE_DEXT_RULE,$(DEXTSRCDIR))))
else
EXCLUDED_SOURCES += $(DEXT_SRCS)
endif

include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.targets
