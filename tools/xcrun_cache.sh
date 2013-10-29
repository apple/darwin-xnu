#!/bin/sh

#
# This shell-script is argument-compatible with xcrun(1) as invoked
# by xnu's Makefiles. Additionally, it supports caching tools
# in the local build directory. It is tightly coupled to exactly
# the queries that MakeInc.cmd makes, in exactly the order it makes
# them. ./tools/remote_build.sh invokes this indirectly in caching
# mode, so '$(XCRUN) -sdk foo -find bar' copies 'bar' from wherever
# it is on-disk into ./BUILD/BuildData, and returns that path to the
# caller. In '-u' mode on a remote build server, cache tools
# relative to the current build directory are returned without
# actually calling through to xcrun(1), since the remote build
# server may not even have Xcode installed.
#

SDKROOT=""
FINDTOOL=""
SDKQUERY=""
VERBOSE=""
OBJROOT=""
CACHE=0

# echo "Calling $0 $@" 1>&2

while [ $# -gt 0 ]; do
    case "$1" in
	-c)
	    CACHE=1
	    shift
	    OBJROOT="$1"
	    shift
	    ;;
	-u)
	    CACHE=0
	    shift
	    OBJROOT="$1"
	    shift
	    ;;
	-sdk)
	    shift
	    SDKROOT="$1"
	    shift
	    ;;
	-verbose)
	    VERBOSE="$1"
	    shift
	    set -x
	    ;;
	-find)
	    shift
	    FINDTOOL="$1"
	    shift
	    ;;
	-show-sdk-path)
	    SDKQUERY="$1"
	    shift
	    ;;
	-show-sdk-platform-path)
	    SDKQUERY="$1"
	    shift
	    ;;
	-show-sdk-version)
	    SDKQUERY="$1"
	    shift
	    ;;
	*)
	    echo "Unrecognized argument $1" 1>&2
	    exit 1
    esac    
done

function CreateFile() {
    local string="$1"
    local filepath="$2"
    echo "${string}" > "${filepath}.new"
    cmp -s "${filepath}" "${filepath}.new"
    if [ $? -eq 0 ]; then
	rm "${filepath}.new"
    else
	mv "${filepath}.new" "${filepath}"
    fi
}

if [ $CACHE -eq 1 ]; then

    if [ -n "$SDKQUERY" ]; then
	# MakeInc.cmd makes SDK queries up-front first. Generally the
	# SDKROOT that is an input to these are one of:
	# "macosx" => Host SDK
	# "iphonehostXXX" => iPhone Host SDK
	# other shortcut or full path => Target SDK
	#
	# Once an initial lookup is made, subsequent SDKROOTs for
	# that same SDK may use a full path or cached path
	SDKTYPE=""
	case "$SDKROOT" in
	    macosx)
		SDKTYPE="host"
		;;
	    iphonehost*)
		SDKTYPE="iphonehost"
		;;
	    *)
		if [ -f "$SDKROOT/.sdktype" ]; then
		    SDKTYPE=`cat "$SDKROOT/.sdktype"`
		else
		    SDKTYPE="target"
		fi
		;;
	esac

	# A cached SDK path can be passed to xcrun, so
	# we need the original on-disk path
	if [ -f "$SDKROOT/.realsdkpath" ]; then
	    REALSDKROOT=`cat "$SDKROOT/.realsdkpath"`
	else
	    REALSDKROOT="$SDKROOT"
	fi

	SDKPROPERTY=`/usr/bin/xcrun $VERBOSE -sdk "$REALSDKROOT" "$SDKQUERY"`
	if [ $? -ne 0 ]; then
	    exit $?
	fi
	
	case $SDKQUERY in
	    -show-sdk-path)
		# Cache the SDK locally, and transform the resulting SDKPROPERTY
		if [ -z "$SDKPROPERTY" ]; then
		    SDKPROPERTY="/"
		    SDKNAME="Slash.sdk"
		else
		    SDKNAME=$(basename "${SDKPROPERTY}")
		fi
		mkdir -p "${OBJROOT}/BuildTools/${SDKNAME}"
		mkdir -p "${OBJROOT}/BuildTools/${SDKNAME}/usr/include"
		rsync -aq --exclude=c++ --exclude=php --exclude=soc "${SDKPROPERTY}/usr/include/" "${OBJROOT}/BuildTools/${SDKNAME}/usr/include/"
		if [ "$SDKTYPE" = "iphonehost" ]; then
		    mkdir -p "${OBJROOT}/BuildTools/${SDKNAME}/usr/local/lib/system"
		    rsync -aq "${SDKPROPERTY}/usr/local/lib/system/" "${OBJROOT}/BuildTools/${SDKNAME}/usr/local/lib/system/"
		else
		    mkdir -p "${OBJROOT}/BuildTools/${SDKNAME}/usr/lib"
		    rsync -aq "${SDKPROPERTY}/usr/lib/libSystem"* "${OBJROOT}/BuildTools/${SDKNAME}/usr/lib/"
		    rsync -aq "${SDKPROPERTY}/usr/lib/libc++"* "${OBJROOT}/BuildTools/${SDKNAME}/usr/lib/"
		    rsync -aq "${SDKPROPERTY}/usr/lib/libstdc++"* "${OBJROOT}/BuildTools/${SDKNAME}/usr/lib/"
		    mkdir -p "${OBJROOT}/BuildTools/${SDKNAME}/usr/lib/system"
		    rsync -aq --exclude=\*_debug.dylib --exclude=\*_profile.dylib "${SDKPROPERTY}/usr/lib/system/" "${OBJROOT}/BuildTools/${SDKNAME}/usr/lib/system/"
		fi
		if [ -f "${SDKPROPERTY}/usr/local/libexec/availability.pl" ]; then
		    mkdir -p "${OBJROOT}/BuildTools/${SDKNAME}/usr/local/libexec"
		    rsync -aq "${SDKPROPERTY}/usr/local/libexec/availability.pl" "${OBJROOT}/BuildTools/${SDKNAME}/usr/local/libexec/"
		fi
		CreateFile "${SDKPROPERTY}" "${OBJROOT}/BuildTools/${SDKNAME}/.realsdkpath"
		CreateFile "${SDKTYPE}" "${OBJROOT}/BuildTools/${SDKNAME}/.sdktype"
		CreateFile "BuildTools/${SDKNAME}" "${OBJROOT}/BuildTools/.${SDKTYPE}sdk"
		echo "${OBJROOT}/BuildTools/${SDKNAME}"
		exit 0
		;;
	    -show-sdk-platform-path)
		PLATFORMNAME=$(basename "${SDKPROPERTY}")
		mkdir -p "${OBJROOT}/BuildTools/${PLATFORMNAME}"
		if [ -f "${SDKPROPERTY}/usr/local/standalone/firmware/device_map.db" ]; then
		    mkdir -p "${OBJROOT}/BuildTools/${PLATFORMNAME}/usr/local/standalone/firmware"
		    rsync -aq "${SDKPROPERTY}/usr/local/standalone/firmware/device_map.db" \
			"${OBJROOT}/BuildTools/${PLATFORMNAME}/usr/local/standalone/firmware/"
		fi
		CreateFile "BuildTools/${PLATFORMNAME}" "${OBJROOT}/BuildTools/.targetplatform"
		echo "${OBJROOT}/BuildTools/${PLATFORMNAME}"
		exit 0
		;;
	    -show-sdk-version)
		CreateFile "${SDKPROPERTY}" "${OBJROOT}/BuildTools/.targetsdkversion"
		echo "${SDKPROPERTY}"
		exit 0
		;;
	esac

    elif [ -n "$FINDTOOL" ]; then

	# We assume SDK Queries have been performed first and subsequent
	# SDKROOTs used to find tools are all using cached SDKs in
	# the build directory, in which case metadata is present

	if [ ! -f "$SDKROOT/.realsdkpath" ]; then
	    exit 1
	fi
	REALSDKROOT=`cat "$SDKROOT/.realsdkpath"`

	if [ ! -f "$SDKROOT/.sdktype" ]; then
	    exit 1
	fi
	SDKTYPE=`cat "$SDKROOT/.sdktype"`

	TOOLPATH=`/usr/bin/xcrun $VERBOSE -sdk "$REALSDKROOT" -find "$FINDTOOL"`
	if [ $? -ne 0 ]; then
	    exit $?
	fi

	# Keep the parent directory when caching tools, along with Host vs. Target
	TOOLNAME=$(basename "${TOOLPATH}")
	TOOLDIR=$(basename $(dirname "${TOOLPATH}"))
	if [ "$SDKTYPE" = "host" ]; then
	    NEWTOOLPATH="${OBJROOT}/BuildTools/Host/${TOOLDIR}/${TOOLNAME}"
	    mkdir -p "${OBJROOT}/BuildTools/Host"
	    CreateFile "BuildTools/Host/${TOOLDIR}/${TOOLNAME}" "${OBJROOT}/BuildTools/Host/.${TOOLNAME}"
	else
	    NEWTOOLPATH="${OBJROOT}/BuildTools/Target/${TOOLDIR}/${TOOLNAME}"
	    mkdir -p "${OBJROOT}/BuildTools/Target"
	    CreateFile "BuildTools/Target/${TOOLDIR}/${TOOLNAME}" "${OBJROOT}/BuildTools/Target/.${TOOLNAME}"
	fi
	mkdir -p $(dirname "${NEWTOOLPATH}")
	rsync -aq "${TOOLPATH}" "${NEWTOOLPATH}"
	case "${TOOLNAME}" in
	    clang)
		mkdir -p $(dirname $(dirname "${NEWTOOLPATH}"))/lib/clang
		rsync -aq $(dirname "${TOOLPATH}")/ld $(dirname "${NEWTOOLPATH}")/ld
		rsync -aq $(dirname $(dirname "${TOOLPATH}"))/lib/clang/ $(dirname $(dirname "${NEWTOOLPATH}"))/lib/clang/
		rsync -aq $(dirname $(dirname "${TOOLPATH}"))/lib/libLTO.dylib $(dirname $(dirname "${NEWTOOLPATH}"))/lib/libLTO.dylib
		;;
	    bison)
		mkdir -p $(dirname $(dirname "${NEWTOOLPATH}"))/share/bison
		rsync -aq $(dirname $(dirname "${TOOLPATH}"))/share/bison/ $(dirname $(dirname "${NEWTOOLPATH}"))/share/bison/
		;;
	esac

	echo "${NEWTOOLPATH}"
	exit 0
    else
	echo "Unrecognized option" 1>&2
	exit 1
    fi
fi

# When using cached SDK information, first try to do
# an initial classification, and then read properties from
# cached locations
SDKTYPE=""
case "$SDKROOT" in
    macosx)
	SDKTYPE="host"
	;;
    iphonehost*)
	SDKTYPE="iphonehost"
	;;
    *)
	if [ -f "$SDKROOT/.sdktype" ]; then
	    SDKTYPE=`cat "$SDKROOT/.sdktype"`
	else
	    SDKTYPE="target"
	fi
	;;
esac

if [ -n "$FINDTOOL" ]; then
    TOOLNAME=$(basename "${FINDTOOL}")
    if [ "${SDKTYPE}" = "host" ]; then
	RELPATH=`cat ${OBJROOT}/BuildTools/Host/.${TOOLNAME}`
    else
	RELPATH=`cat ${OBJROOT}/BuildTools/Target/.${TOOLNAME}`
    fi
    echo "${OBJROOT}/${RELPATH}"
else	
    case $SDKQUERY in
	-show-sdk-path)
	    RELPATH=`cat ${OBJROOT}/BuildTools/.${SDKTYPE}sdk`
	    echo "${OBJROOT}/${RELPATH}"
	    ;;
	-show-sdk-platform-path)
	    RELPATH=`cat ${OBJROOT}/BuildTools/.targetplatform`
	    echo "${OBJROOT}/${RELPATH}"
	    ;;
	-show-sdk-version)
	    echo `cat ${OBJROOT}/BuildTools/.targetsdkversion`
	    ;;
    esac
fi
