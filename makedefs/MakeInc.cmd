#
# Commands for the build environment
#
##
# Verbosity
##
ifeq ($(RC_XBS),YES)
VERBOSE = YES
else
VERBOSE = NO
endif
ifeq ($(VERBOSE),YES)
_v =
_vstdout =
else
_v = @
_vstdout = > /dev/null
endif

ifeq ($(VERBOSE),YES)
	XCRUN = /usr/bin/xcrun -verbose -log
else
	XCRUN = /usr/bin/xcrun
endif

SDKROOT ?= /
HOST_SDKROOT ?= /

ifeq ($(PLATFORM),)
	export PLATFORM := $(shell xcodebuild -sdk $(SDKROOT) -version PlatformPath | head -1 | sed 's,^.*/\([^/]*\)\.platform$$,\1,')
	ifeq ($(PLATFORM),)
		export PLATFORM := MacOSX
	endif
endif

# CC/CXX get defined by make(1) by default, so we can't check them
# against the empty string to see if they haven't been set
ifeq ($(origin CC),default)
ifneq ($(findstring iPhone,$(PLATFORM)),)
	export CC := $(shell $(XCRUN) -sdk $(SDKROOT) -find gcc-4.2)
else
	export CC := $(shell $(XCRUN) -sdk $(SDKROOT) -find cc)
endif
endif
ifeq ($(origin CXX),default)
ifneq ($(findstring iPhone,$(PLATFORM)),)
	export CXX := $(shell $(XCRUN) -sdk $(SDKROOT) -find g++-4.2)
else
	export CXX := $(shell $(XCRUN) -sdk $(SDKROOT) -find c++)
endif
endif
ifeq ($(MIG),)
	export MIG := $(shell $(XCRUN) -sdk $(SDKROOT) -find mig)
endif
ifeq ($(MIGCC),)
	export MIGCC := $(CC)
endif
ifeq ($(RELPATH),)
	export RELPATH := $(shell $(XCRUN) -sdk $(SDKROOT) -find relpath)
endif
ifeq ($(STRIP),)
	export STRIP := $(shell $(XCRUN) -sdk $(SDKROOT) -find strip)
endif
ifeq ($(LIPO),)
	export LIPO := $(shell $(XCRUN) -sdk $(SDKROOT) -find lipo)
endif
ifeq ($(LIBTOOL),)
	export LIBTOOL := $(shell $(XCRUN) -sdk $(SDKROOT) -find libtool)
endif
ifeq ($(NM),)
	export NM := $(shell $(XCRUN) -sdk $(SDKROOT) -find nm)
endif
ifeq ($(UNIFDEF),)
	export UNIFDEF := $(shell $(XCRUN) -sdk $(SDKROOT) -find unifdef)
endif
ifeq ($(DECOMMENT),)
	export DECOMMENT := $(shell $(XCRUN) -sdk $(SDKROOT) -find decomment)
endif
ifeq ($(DSYMUTIL),)
	export DSYMUTIL := $(shell $(XCRUN) -sdk $(SDKROOT) -find dsymutil)
endif
ifeq ($(CTFCONVERT),)
	export CTFCONVERT := $(shell $(XCRUN) -sdk $(SDKROOT) -find ctfconvert)
endif
ifeq ($(CTFMERGE),)
	export CTFMERGE :=  $(shell $(XCRUN) -sdk $(SDKROOT) -find ctfmerge)
endif
ifeq ($(CTFSCRUB),)
	export CTFSCRUB := $(shell $(XCRUN) -sdk $(SDKROOT) -find ctfdump) -r
endif
ifeq ($(NMEDIT),)
	export NMEDIT := $(shell $(XCRUN) -sdk $(SDKROOT) -find nmedit)
endif

# Platform-specific tools
ifneq ($(findstring iPhone,$(PRODUCT)),)
ifeq ($(IPHONEOS_OPTIMIZE),)
	export IPHONEOS_OPTIMIZE := $(shell $(XCRUN) -sdk $(SDKROOT) -find iphoneos-optimize)
endif
endif

# Scripts or tools we build ourselves
SEG_HACK := $(OBJROOT)/SETUP/setsegname/setsegname
KEXT_CREATE_SYMBOL_SET := $(OBJROOT)/SETUP/kextsymboltool/kextsymboltool
NEWVERS = $(SRCROOT)/config/newvers.pl

# Standard BSD tools
MD = /usr/bin/md
RM = /bin/rm -f
CP = /bin/cp
MV = /bin/mv
LN = /bin/ln -fs
CAT = /bin/cat
MKDIR = /bin/mkdir -p
FIND = /usr/bin/find
INSTALL = /usr/bin/install
TAR = /usr/bin/gnutar
BASENAME = /usr/bin/basename
TR = /usr/bin/tr

# Platform-specific tools
ifeq (iPhoneOS,$(PLATFORM))
ifeq ($(IPHONEOS_OPTIMIZE),)
	export IPHONEOS_OPTIMIZE := $(shell $(XCRUN) -sdk $(SDKROOT) -find iphoneos-optimize || echo /usr/bin/true)
endif
endif

CTFINSERT = $(XCRUN) -sdk $(SDKROOT) ctf_insert

#
# Command to generate host binaries. Intentionally not
# $(CC), which controls the target compiler
#
ifeq ($(HOST_CC),)
	export HOST_CC		:= $(shell $(XCRUN) -sdk $(HOST_SDKROOT) -find cc)
endif
ifeq ($(HOST_FLEX),)
	export HOST_FLEX	:= $(shell $(XCRUN) -sdk $(HOST_SDKROOT) -find flex)
endif
ifeq ($(HOST_BISON),)
	export HOST_BISON	:= $(shell $(XCRUN) -sdk $(HOST_SDKROOT) -find bison)
endif
ifeq ($(HOST_CODESIGN),)
	export HOST_CODESIGN	:= $(shell $(XCRUN) -sdk $(HOST_SDKROOT) -find codesign)
endif

#
# Command to build libkmod.a/libkmodc++.a, which are
# linked into kext binaries, and should be built as if
# they followed system-wide policies
#
ifeq ($(LIBKMOD_CC),)
	export LIBKMOD_CC	:= $(shell $(XCRUN) -sdk $(SDKROOT) -find cc)
endif

# vim: set ft=make:
