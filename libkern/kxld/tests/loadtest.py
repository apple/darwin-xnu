##
# Copyright (c) 2009 Apple Inc. All rights reserved.
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
##

#!/usr/bin/env python

import sys
from subprocess import call, Popen, PIPE

kexts = []
pipe = Popen("/usr/sbin/kextfind \( -l -and -x -and -arch i386 \)", shell=True, stdout=PIPE).stdout

line = pipe.readline()
while line:
    kexts.append(line.strip())
    line = pipe.readline()

NULL = open("/dev/null")

for kext in kexts:
    try:
        print "Processing", kext
#cmd = "/sbin/kextload -ns /tmp/syms \"%s\"" % kext
        cmd = "/sbin/kextload \"%s\"" % kext
        kextload = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
        for i in range(20):
            kextload.stdin.write("0x1000\n");
        retcode = kextload.wait()
        if retcode < 0:
            print >>sys.stderr, "*** kextload of %s was terminated by signal %d" % (kext, -retcode)
        elif retcode > 0:
            print >>sys.stderr, "*** kextload of %s failed with return code %d" % (kext, retcode)
    except OSError, e:
        print >>sys.stderr, "Execution failed:", e
        sys.exit(1)

