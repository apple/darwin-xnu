#!/bin/bash

#
# Copyright (c) 2008 Apple Inc. All rights reserved.
#
# @APPLE_OSREFERENCE_LICENSE_HEADER_START@
# 
# This file contains Original Code and/or Modifications of Original Code
# as defined in and that are subject to the Apple Public Source License
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. Please obtain a copy of the License at
# http://www.opensource.apple.com/apsl/ and read it before using this
# file.
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
# list_supported.sh <directory with .exports files> <lower case architecture> <target file>

CONFIG_DIR=$1 
ARCH=$2
TARGET_FILE=$3

SUPPORTED_KPI_FILES=( BSDKernel Mach IOKit Libkern )
DEPENDENCY_NAMES=( com.apple.kpi.bsd com.apple.kpi.mach com.apple.kpi.iokit com.apple.kpi.libkern )

rm -f $TARGET_FILE

if [ ${ARCH} == "ALL" ]
then 
	echo "The following symbols are considered sustainable KPI on all architectures." >> $TARGET_FILE
	echo "Note that symbols may be exported by some (or all) architectures individually." >> $TARGET_FILE
else
	echo "The following symbols are considered sustainable KPI on architecture ${ARCH}." >> $TARGET_FILE
fi
echo  >> $TARGET_FILE

for (( i = 0 ; i < ${#SUPPORTED_KPI_FILES[@]} ; i++ ))
do
	echo "Exported by ${DEPENDENCY_NAMES[i]}:" >> $TARGET_FILE
	echo >> $TARGET_FILE
	if [  $ARCH == "ALL" ]
	then
		cat "${CONFIG_DIR}/${SUPPORTED_KPI_FILES[i]}.exports" | sed "s/^_//" | sed "s/:.*//" | sort >> $TARGET_FILE
	else
		cat "${CONFIG_DIR}/${SUPPORTED_KPI_FILES[i]}.${ARCH}.exports" | sed "s/^_//" | sed "s/:.*//" | sort  >> $TARGET_FILE
	fi
	echo >> $TARGET_FILE
done
