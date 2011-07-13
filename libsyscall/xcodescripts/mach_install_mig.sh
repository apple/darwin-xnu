#!/bin/sh
#
# Copyright (c) 2010 Apple Inc. All rights reserved.
#
# @APPLE_OSREFERENCE_LICENSE_HEADER_START@
# 
# This file contains Original Code and/or Modifications of Original Code
# as defined in and that are subject to the Apple Public Source License
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. The rights granted to you under the License
# may not be used to create, or enable the creation or redistribution of,
# unlawful or unlicensed copies of an Apple operating system, or to
# circumvent, violate, or enable the circumvention or violation of, any
# terms of an Apple operating system software license agreement.
# 
# Please obtain a copy of the License at
# http://www.opensource.apple.com/apsl/ and read it before using this file.
# 
# The Original Code and all software distributed under the License are
# distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
# Please see the License for the specific language governing rights and
# limitations under the License.
# 
# @APPLE_OSREFERENCE_LICENSE_HEADER_END@
#

# build inside OBJROOT
cd $OBJROOT

# check if we're building for the simulator
[ "$RC_ProjectName" == "Libmach_Sim" ] && DSTROOT="$DSTROOT$SDKROOT"

MIG=`xcrun -sdk "$SDKROOT" -find mig`
MIGCC=`xcrun -sdk "$SDKROOT" -find cc`
export MIGCC
MIG_DEFINES="-DLIBSYSCALL_INTERFACE"
MIG_HEADER_DST="$DSTROOT/usr/include/mach"
SERVER_HEADER_DST="$DSTROOT/usr/include/servers"
# from old Libsystem makefiles
MACHINE_ARCH=`echo $ARCHS | cut -d' ' -f 1`
SRC="$SRCROOT/mach"

MIGS="clock.defs
	clock_priv.defs
	clock_reply.defs
	exc.defs
	host_priv.defs
	host_security.defs
	ledger.defs
	lock_set.defs
	mach_port.defs
	mach_host.defs
	mach_vm.defs
	processor.defs
	processor_set.defs
	vm_map.defs"

MIGS_ARCH="thread_act.defs
	task.defs"

SERVER_HDRS="key_defs.h
	ls_defs.h
	netname_defs.h
	nm_defs.h"

# install /usr/include/server headers 
mkdir -p $SERVER_HEADER_DST
for hdr in $SERVER_HDRS; do
	install -o 0 -c -m 444 $SRC/servers/$hdr $SERVER_HEADER_DST
done

# special case because we only have one to do here
$MIG -arch $MACHINE_ARCH -header "$SERVER_HEADER_DST/netname.h" $SRC/servers/netname.defs

# install /usr/include/mach mig headers

mkdir -p $MIG_HEADER_DST

for mig in $MIGS; do
	MIG_NAME=`basename $mig .defs`
	$MIG -arch $MACHINE_ARCH -cc $MIGCC -header "$MIG_HEADER_DST/$MIG_NAME.h" $MIG_DEFINES $SRC/$mig
done

ARCHS=`echo $ARCHS | sed -e 's/armv./arm/g'`
for arch in $ARCHS; do
	MIG_ARCH_DST="$MIG_HEADER_DST/$arch"

	mkdir -p $MIG_ARCH_DST

	for mig in $MIGS_ARCH; do
		MIG_NAME=`basename $mig .defs`
		$MIG -arch $MACHINE_ARCH -cc $MIGCC -header "$MIG_ARCH_DST/$MIG_NAME.h" $MIG_DEFINES $SRC/$mig
	done	
done
