#! /bin/bash -
#
# Copyright (c) 2010 Apple Inc. All rights reserved.
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

function usage() {
    echo "Usage: $0 <sdk> <output>" 1>&2
    exit 1
}

if [ $# -ne 2 ]; then
    usage
fi

SDKROOT="$1"
OUTPUT="$2"

AVAILABILITY_PL="${SDKROOT}/${DRIVERKITROOT}/usr/local/libexec/availability.pl"

if [ ! -x "${AVAILABILITY_PL}" ] ; then
    echo "Unable to locate ${AVAILABILITY_PL} (or not executable)" >&2
    exit 1
fi
	    
{
cat <<EOF
/* Copyright (c) 2010 Apple Inc. All rights reserved.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef _CDEFS_H_
# error "Never use <sys/_symbol_aliasing.h> directly.  Use <sys/cdefs.h> instead."
#endif

EOF

for ver in $(${AVAILABILITY_PL} --ios) ; do
    set -- $(echo "$ver" | tr '.' ' ')
    ver_major=$1
    ver_minor=$2
    ver_rel=$3
    if [ -z "$ver_rel" ]; then
	    # don't produce these defines for releases with tertiary release numbers
        value=$(printf "%d%02d00" ${ver_major} ${ver_minor})
        str=$(printf "__IPHONE_%d_%d" ${ver_major} ${ver_minor})
        echo "#if defined(__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ >= ${value}"
        echo "#define __DARWIN_ALIAS_STARTING_IPHONE_${str}(x) x"
        echo "#else"
        echo "#define __DARWIN_ALIAS_STARTING_IPHONE_${str}(x)"
        echo "#endif"
        echo ""
    fi
done

for ver in $(${AVAILABILITY_PL} --macosx) ; do
    set -- $(echo "$ver" | tr '.' ' ')
    ver_major=$1
    ver_minor=$2
    ver_rel=$3
    if [ -z "$ver_rel" ]; then
	ver_rel=0
    fi
    if [ "$ver_major" -lt 10 -o \( "$ver_major" -eq 10 -a "$ver_minor" -lt 10 \) ]; then
	value=$(printf "%d%d0" ${ver_major} ${ver_minor})
	str=$(printf "__MAC_%d_%d" ${ver_major} ${ver_minor})
    else
	value=$(printf "%d%02d%02d" ${ver_major} ${ver_minor} ${ver_rel})
	if [ "$ver_rel" -gt 0 ]; then
	    str=$(printf "__MAC_%d_%d_%d" ${ver_major} ${ver_minor} ${ver_rel})
	else
	    str=$(printf "__MAC_%d_%d" ${ver_major} ${ver_minor})
	fi
    fi
    echo "#if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= ${value}"
    echo "#define __DARWIN_ALIAS_STARTING_MAC_${str}(x) x"
    echo "#else"
    echo "#define __DARWIN_ALIAS_STARTING_MAC_${str}(x)"
    echo "#endif"
    echo ""
done
} > "$OUTPUT"

