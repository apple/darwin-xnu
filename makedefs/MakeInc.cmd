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

CC := $(XCRUN) -sdk $(SDKROOT) cc
CXX := $(XCRUN) -sdk $(SDKROOT) g++
MIG := $(XCRUN) -sdk $(SDKROOT) mig
ifeq ($(MIGCC),)
	export MIGCC := $(shell $(XCRUN) -sdk $(SDKROOT) -find cc)
endif
ifeq ($(RELPATH),)
	export RELPATH := $(shell $(XCRUN) -sdk $(SDKROOT) -find relpath)
endif
SEG_HACK := $(XCRUN) -sdk $(SDKROOT) setsegname
KEXT_CREATE_SYMBOL_SET := $(XCRUN) -sdk $(SDKROOT) kextsymboltool

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
STRIP = $(XCRUN) -sdk $(SDKROOT) strip
LIPO = $(XCRUN) -sdk $(SDKROOT) lipo
LIBTOOL = $(XCRUN) -sdk $(SDKROOT) libtool
NM = $(XCRUN) -sdk $(SDKROOT) nm

BASENAME = /usr/bin/basename
TR = /usr/bin/tr

UNIFDEF   = $(XCRUN) -sdk $(SDKROOT) unifdef
DECOMMENT = /usr/local/bin/decomment
NEWVERS = $(SRCROOT)/config/newvers.pl

DSYMUTIL = $(XCRUN) -sdk $(SDKROOT) dsymutil
CTFCONVERT = $(XCRUN) -sdk $(SDKROOT) ctfconvert
CTFMERGE =  $(XCRUN) -sdk $(SDKROOT) ctfmerge
CTFSCRUB = $(XCRUN) -sdk $(SDKROOT) ctfdump -r

# vim: set ft=make:
